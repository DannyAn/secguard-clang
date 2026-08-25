package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type MemoryLeakDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewMemoryLeakDetector(store db.Store, p *parser.Parser, logger *log.Logger) *MemoryLeakDetector {
	return &MemoryLeakDetector{store: store, parser: p, logger: logger}
}

func (d *MemoryLeakDetector) Name() string { return "memory_leak" }

func (d *MemoryLeakDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("memory_leak: list functions: %w", err)
	}

	funcMap := make(map[string]*db.Function, len(funcs))
	for _, f := range funcs {
		funcMap[f.Name] = f
	}

	// Scan for free() sites once per file so the RAII create/destroy pairing
	// below no longer re-reads + re-parses each destroy function's file from
	// disk per candidate (the old functionHasFrees path).
	freeFuncs := make(map[int64]bool)
	hasDestroyCandidates := false
	for _, f := range funcs {
		if destroyName := getDestroyCounterpart(f.Name); destroyName != "" {
			if _, exists := funcMap[destroyName]; exists {
				hasDestroyCandidates = true
			}
		}
	}
	if hasDestroyCandidates {
		if err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
			calls := root.FindAll("call_expression")
			for _, f := range fileFuncs {
				if freeFuncs[f.ID] {
					continue
				}
				for _, call := range calls {
					if !funcLineRange(f, call.StartLine()) {
						continue
					}
					if extractCallName(call) == "free" {
						freeFuncs[f.ID] = true
						break
					}
				}
			}
		}); err != nil {
			return result, fmt.Errorf("memory_leak: scan frees: %w", err)
		}
	}

	raiiCreateFuncs := make(map[int64]bool)
	for _, f := range funcs {
		if destroyName := getDestroyCounterpart(f.Name); destroyName != "" {
			if destroyFunc, exists := funcMap[destroyName]; exists {
				if freeFuncs[destroyFunc.ID] {
					raiiCreateFuncs[f.ID] = true
				}
			}
		}
	}

	err = forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		decls := root.FindAll("declaration")
		ifs := root.FindAll("if_statement")
		macros := macroFreeSummaries(root)

		for _, f := range fileFuncs {
			allocs := d.findAllocations(ctx, f, file, assigns, inits)
			frees := d.findFrees(ctx, f, file, calls, macros)
			returnLines := findReturnLinesFrom(returns, f)

			isRAII := raiiCreateFuncs[f.ID]

			body := bodies[f.StartLine]
			cfg := graph.BuildStmtCFG(body, f.EndLine)
			cfgValid := body.Kind() == "compound_statement"
			localVars := findLocalVarsFrom(decls, f)

			for varName, allocLine := range allocs {
				freeLines, hasFree := frees[varName]
				isReturned := isReturnedToCaller(varName, returns, f)
				filteredReturns := filterNullGuardReturns(ifs, returnLines, varName)
				nullGuardReturns := subtractLines(returnLines, filteredReturns)
				escapeLines := findEscapeLines(assigns, f, varName, localVars)

				shouldReportLeak := false
				shouldReportRelease := false

				if isReturned {
					shouldReportRelease = true
				} else if !hasFree {
					// A malloc with no free is still not a leak when its result
					// escapes at the allocation site (stored to a global/array).
					if containsLine(escapeLines, allocLine) {
						shouldReportRelease = true
					} else {
						shouldReportLeak = true
					}
				} else if cfgValid {
					if hasLeakingPath(cfg, allocLine, freeLines, nullGuardReturns, escapeLines) {
						shouldReportLeak = true
					} else {
						shouldReportRelease = true
					}
				} else {
					shouldReportRelease = true
				}

				if shouldReportLeak && !isRAII {
					if emitEvent(ctx, d.store, d.logger, "MEMORY_ALLOC", f.ID, &db.Location{FileID: file.ID, Line: allocLine}, map[string]string{
						"variable": varName,
						"origin":   "malloc",
					}) {
						result.EventsCreated++
					}
				}

				if shouldReportRelease {
					if emitEvent(ctx, d.store, d.logger, "MEMORY_ALLOC", f.ID, &db.Location{FileID: file.ID, Line: allocLine}, map[string]string{
						"variable": varName,
						"origin":   "malloc",
					}) {
						result.EventsCreated++
					}
					releaseLine := allocLine
					if len(freeLines) > 0 {
						releaseLine = freeLines[0]
					}
					if emitEvent(ctx, d.store, d.logger, "MEMORY_RELEASE", f.ID, &db.Location{FileID: file.ID, Line: releaseLine}, map[string]string{
						"variable": varName,
						"origin":   "free",
					}) {
						result.EventsCreated++
					}
				}
			}
		}
	})
	return result, err
}

func (d *MemoryLeakDetector) findAllocations(ctx context.Context, f *db.Function, file *db.File, assigns, inits []parser.Node) map[string]int {
	allocs := make(map[string]int)

	checkNode := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs, rhs := children[0], children[1]
		// Only a real malloc/calloc/realloc CALL on the right-hand side is an
		// allocation. A substring match would treat `strm->zalloc = zcalloc`
		// (assigning an allocator function pointer) as an allocation because
		// "zcalloc" contains "calloc".
		if !isMallocExpr(rhs) {
			return
		}
		varName := ""
		if lhs.Kind() == "identifier" {
			varName = lhs.Text()
		} else {
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					varName = child.Text()
					break
				}
			}
		}
		if varName != "" {
			allocs[varName] = node.StartLine()
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}

	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}

	return allocs
}

func (d *MemoryLeakDetector) findFrees(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, macros map[string]macroFreeSummary) map[string][]int {
	frees := make(map[string][]int)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		// A freeing function-like macro (free-only or free+null) releases its
		// first argument; the free inside the macro is invisible to tree-sitter.
		if s, ok := macros[callName]; ok && s.freesArg {
			if args := getCallArgs(call); len(args) > 0 && args[0].Kind() == "identifier" {
				frees[args[0].Text()] = append(frees[args[0].Text()], call.StartLine())
			}
			continue
		}
		if callName != "free" {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() == "argument_list" {
				for _, arg := range child.NamedChildren() {
					if arg.Kind() == "identifier" {
						frees[arg.Text()] = append(frees[arg.Text()], call.StartLine())
					}
				}
			}
		}
	}
	return frees
}

func findReturnLinesFrom(returns []parser.Node, f *db.Function) []int {
	var returnLines []int
	for _, ret := range returns {
		if funcLineRange(f, ret.StartLine()) {
			returnLines = append(returnLines, ret.StartLine())
		}
	}
	return returnLines
}

func filterNullGuardReturns(ifs []parser.Node, returnLines []int, varName string) []int {
	if varName == "" {
		return returnLines
	}
	guarded := make(map[int]bool)
	for _, ifStmt := range ifs {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if !isNullCheckCondition(cond, varName) {
			continue
		}
		consequence := ifStmt.ChildByFieldName("consequence")
		if consequence == nil {
			continue
		}
		for _, ret := range consequence.FindAll("return_statement") {
			guarded[ret.StartLine()] = true
		}
	}
	var result []int
	for _, line := range returnLines {
		if !guarded[line] {
			result = append(result, line)
		}
	}
	return result
}

func isNullCheckCondition(cond *parser.Node, varName string) bool {
	condText := cond.Text()
	if strings.Contains(condText, "!"+varName) {
		return true
	}
	if strings.Contains(condText, varName+" == NULL") || strings.Contains(condText, varName+" == 0") {
		return true
	}
	if strings.Contains(condText, "NULL == "+varName) || strings.Contains(condText, "0 == "+varName) {
		return true
	}
	// Assignment-in-condition: `(var = malloc(...)) == NULL` is the short-circuit
	// guard for a malloc inside an if condition (`if (fd == -1 || (path = malloc(n))
	// == NULL) return NULL;`). var is assigned, then compared against NULL; the
	// branch returns on failure, so it is a null-guard early return, not a leak.
	if strings.Contains(condText, "("+varName+" =") && strings.Contains(condText, "== NULL") {
		return true
	}
	return false
}

// hasLeakingPath reports whether there is a control-flow path from the
// allocation to the function exit that avoids every free, every null-guard
// early return, and every "escape" (the pointer being returned or stored to a
// non-local). It uses the statement-level CFG so flat functions (an `if` with
// an expression body) no longer degenerate to a path-insensitive fallback.
func hasLeakingPath(cfg *graph.StmtCFG, allocLine int, freeLines []int, nullGuardReturns []int, escapeLines []int) bool {
	if cfg == nil {
		return false
	}
	allocNode := cfg.NodeAt(allocLine)
	if allocNode == nil {
		return true // cannot prove non-leak; report conservatively
	}
	avoid := make(map[int]bool, len(freeLines)+len(nullGuardReturns)+len(escapeLines))
	for _, l := range freeLines {
		if n := cfg.NodeAt(l); n != nil {
			avoid[n.ID] = true
		}
	}
	for _, l := range nullGuardReturns {
		if n := cfg.NodeAt(l); n != nil {
			avoid[n.ID] = true
		}
	}
	for _, l := range escapeLines {
		if n := cfg.NodeAt(l); n != nil {
			avoid[n.ID] = true
		}
	}
	return cfg.ReachesAvoiding(allocNode.ID, avoid, cfg.Exit)
}

// findEscapeLines returns the lines where varName's allocation "escapes" the
// function: it is stored into a subscript/field, or assigned to an identifier
// that is not a local of the function (a global/static). A value that escapes
// is transferred ownership, not leaked.
func findEscapeLines(assigns []parser.Node, f *db.Function, varName string, localVars map[string]bool) []int {
	var lines []int
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs, rhs := children[0], children[1]

		if rhs.Kind() == "identifier" && rhs.Text() == varName {
			if lhs.Kind() == "subscript_expression" || lhs.Kind() == "field_expression" {
				lines = append(lines, assign.StartLine())
			} else if lhs.Kind() == "identifier" && !localVars[lhs.Text()] {
				lines = append(lines, assign.StartLine())
			}
		}
		// A malloc whose result is assigned directly to a non-local identifier
		// (`g = malloc()`) escapes at the allocation site itself.
		if lhs.Kind() == "identifier" && lhs.Text() == varName && !localVars[varName] && isMallocExpr(rhs) {
			lines = append(lines, assign.StartLine())
		}
		// A malloc assigned directly to a field/subscript of a NON-LOCAL base
		// (`state->in = malloc(...)` where state is a parameter) escapes into
		// the struct/array — the field is owned by the caller, which frees it
		// elsewhere (e.g. zlib's gz_state buffers freed by gzclose). A local
		// base (`local.field = malloc(...)`) still leaks if never freed.
		if (lhs.Kind() == "field_expression" || lhs.Kind() == "subscript_expression") && isMallocExpr(rhs) {
			base := ""
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					base = child.Text()
					break
				}
			}
			if base != "" && !localVars[base] {
				lines = append(lines, assign.StartLine())
			}
		}
	}
	return lines
}

// findLocalVars returns the names of variables declared inside the function.
func findLocalVarsFrom(decls []parser.Node, f *db.Function) map[string]bool {
	locals := make(map[string]bool)
	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		for _, child := range decl.NamedChildren() {
			name := extractVarName(child)
			if name != "" && !parser.IsCTypeKeyword(name) {
				locals[name] = true
			}
		}
	}
	return locals
}

// isMallocExpr reports whether expr is (or casts) a malloc/calloc/realloc call.
// Nested casts (`(int)(size_t)malloc(64)`) are unwrapped recursively.
func isMallocExpr(expr parser.Node) bool {
	if expr.Kind() == "cast_expression" {
		for _, c := range expr.NamedChildren() {
			if isMallocExpr(c) {
				return true
			}
		}
		return false
	}
	if expr.Kind() != "call_expression" {
		return false
	}
	switch extractCallName(expr) {
	case "malloc", "calloc", "realloc":
		return true
	}
	return false
}

// containsLine reports whether lines contains target.
func containsLine(lines []int, target int) bool {
	for _, l := range lines {
		if l == target {
			return true
		}
	}
	return false
}

// subtractLines returns all lines in all that are not in remove.
func subtractLines(all, remove []int) []int {
	rm := make(map[int]bool, len(remove))
	for _, l := range remove {
		rm[l] = true
	}
	out := make([]int, 0, len(all))
	for _, l := range all {
		if !rm[l] {
			out = append(out, l)
		}
	}
	return out
}

func isReturnedToCaller(varName string, returns []parser.Node, f *db.Function) bool {
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		for _, child := range ret.NamedChildren() {
			if child.Kind() == "identifier" && child.Text() == varName {
				return true
			}
			if child.Kind() == "parenthesized_expression" {
				for _, inner := range child.NamedChildren() {
					if inner.Kind() == "identifier" && inner.Text() == varName {
						return true
					}
				}
			}
		}
	}
	return false
}

func getDestroyCounterpart(funcName string) string {
	suffixes := []struct{ create, destroy string }{
		{"_create", "_destroy"},
		{"_new", "_free"},
		{"_init", "_deinit"},
		{"_acquire", "_release"},
	}
	for _, s := range suffixes {
		if strings.HasSuffix(funcName, s.create) {
			prefix := funcName[:len(funcName)-len(s.create)]
			return prefix + s.destroy
		}
	}
	return ""
}
