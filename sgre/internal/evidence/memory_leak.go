package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	raiiCreateFuncs := make(map[int64]bool)
	for _, f := range funcs {
		if destroyName := getDestroyCounterpart(f.Name); destroyName != "" {
			if destroyFunc, exists := funcMap[destroyName]; exists {
				if d.functionHasFrees(ctx, destroyFunc) {
					raiiCreateFuncs[f.ID] = true
				}
			}
		}
	}

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		allocs := d.findAllocations(ctx, f, file, root, &result)
		frees := d.findFrees(ctx, f, file, root)
		returnLines := findReturnLines(root, f)

		isRAII := raiiCreateFuncs[f.ID]

		body := extractFunctionBody(root, f.StartLine)
		cfg := graph.BuildStmtCFG(body, f.EndLine)
		cfgValid := body.Kind() == "compound_statement"
		localVars := findLocalVars(root, f)

		for varName, allocLine := range allocs {
			freeLines, hasFree := frees[varName]
			isReturned := isReturnedToCaller(varName, root, f)
			filteredReturns := filterNullGuardReturns(root, returnLines, varName)
			nullGuardReturns := subtractLines(returnLines, filteredReturns)
			escapeLines := findEscapeLines(root, f, varName, localVars)

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
				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: allocLine})
				props, _ := json.Marshal(map[string]string{
					"variable": varName,
					"origin":   "malloc",
				})
				d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "MEMORY_ALLOC",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				result.EventsCreated++
			}

			if shouldReportRelease {
				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: allocLine})
				props, _ := json.Marshal(map[string]string{
					"variable": varName,
					"origin":   "malloc",
				})
				d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "MEMORY_ALLOC",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				releaseLine := allocLine
				if len(freeLines) > 0 {
					releaseLine = freeLines[0]
				}
				releaseLocID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: releaseLine})
				releaseProps, _ := json.Marshal(map[string]string{
					"variable": varName,
					"origin":   "free",
				})
				d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "MEMORY_RELEASE",
					EntityID:   f.ID,
					LocationID: releaseLocID,
					Properties: string(releaseProps),
				})
				result.EventsCreated += 2
			}
		}

		tree.Close()
	}

	return result, nil
}

func (d *MemoryLeakDetector) findAllocations(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) map[string]int {
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

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		checkNode(assign)
	}

	for _, init := range root.FindAll("init_declarator") {
		if init.StartLine() < f.StartLine || init.StartLine() > f.EndLine {
			continue
		}
		checkNode(init)
	}

	return allocs
}

func (d *MemoryLeakDetector) findFrees(ctx context.Context, f *db.Function, file *db.File, root parser.Node) map[string][]int {
	frees := make(map[string][]int)
	calls := root.FindAll("call_expression")
	for _, call := range calls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
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

func findReturnLines(root parser.Node, f *db.Function) []int {
	var returnLines []int
	for _, ret := range root.FindAll("return_statement") {
		if ret.StartLine() >= f.StartLine && ret.StartLine() <= f.EndLine {
			returnLines = append(returnLines, ret.StartLine())
		}
	}
	return returnLines
}

func filterNullGuardReturns(root parser.Node, returnLines []int, varName string) []int {
	if varName == "" {
		return returnLines
	}
	guarded := make(map[int]bool)
	for _, ifStmt := range root.FindAll("if_statement") {
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
func findEscapeLines(root parser.Node, f *db.Function, varName string, localVars map[string]bool) []int {
	var lines []int
	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
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
func findLocalVars(root parser.Node, f *db.Function) map[string]bool {
	locals := make(map[string]bool)
	for _, decl := range root.FindAll("declaration") {
		if decl.StartLine() < f.StartLine || decl.StartLine() > f.EndLine {
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

func isReturnedToCaller(varName string, root parser.Node, f *db.Function) bool {
	for _, ret := range root.FindAll("return_statement") {
		if ret.StartLine() < f.StartLine || ret.StartLine() > f.EndLine {
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

func (d *MemoryLeakDetector) functionHasFrees(ctx context.Context, f *db.Function) bool {
	file, _ := d.store.GetFileByID(ctx, f.FileID)
	if file == nil {
		return false
	}
	source, err := os.ReadFile(file.Path)
	if err != nil {
		return false
	}
	tree, err := d.parser.ParseCached(source, file.Path)
	if err != nil {
		return false
	}
	defer tree.Close()

	root := tree.RootNode()
	calls := root.FindAll("call_expression")
	for _, call := range calls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		if extractCallName(call) == "free" {
			return true
		}
	}
	return false
}
