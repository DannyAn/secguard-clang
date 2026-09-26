package evidence

import (
	"context"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
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

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
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
			allocs := d.findAllocations(ctx, f, file, assigns, inits, calls)
			frees := d.findFrees(ctx, f, file, calls, macros, inits, assigns)
			returnLines := findReturnLinesFrom(returns, f)

			body := bodies[f.StartLine]
			cfg := graph.BuildStmtCFG(body, f.EndLine)
			cfgValid := body.Kind() == "compound_statement"
			localVars := findLocalVarsFrom(decls, f)

			for varName, allocLines := range allocs {
				freeLines, hasFree := frees[varName]
				// realloc into a DIFFERENT target (`tmp = realloc(p, n)`) consumes
				// p's block on success and leaves p reachable on failure, so p is
				// never leaked by that call — model it as a release at the realloc
				// line so p is not reported.
				for _, l := range findReallocConsumeLines(assigns, inits, f, varName) {
					freeLines = append(freeLines, l)
				}
				// self-realloc `p = realloc(p, n)` leaks the OLD block when realloc
				// fails (returns NULL) — ML-12.
				selfReallocLines := findSelfReallocLines(assigns, inits, f, varName)
				// Lines where a `return varName` hands the pointer to the caller.
				// A return on ONE path is an ownership transfer on that path only;
				// the path-sensitive analysis below treats it as a leak-avoiding
				// node rather than (the old, coarse) a function-wide transfer flag,
				// so `if (err) return p; ...` no longer suppresses a leak on the
				// non-returning path.
				transferLines := findReturnVarLines(varName, returns, f)
				filteredReturns := filterNullGuardReturns(ifs, returnLines, varName)
				nullGuardReturns := subtractLines(returnLines, filteredReturns)
				escapeLines := findEscapeLines(assigns, f, varName, localVars)
				overwriteLines := writeLinesFor(assigns, inits, f, varName)

				for _, allocLine := range allocLines {
					shouldReportLeak := false
					shouldReportRelease := false

					if isGuardedRelease(ifs, varName, freeLines) {
						// Released only inside a positive guard (`if (p) { free(p); }`):
						// the NULL path carries no allocation, so skipping the free on
						// that branch is not a leak. Mirrors resource-leak's guarded-
						// release branch (isGuardedRelease is shared across detectors).
						shouldReportRelease = true
					} else if cfgValid {
						if hasLostResource(cfg, allocLine, freeLines, nullGuardReturns, escapeLines, transferLines, overwriteLines) {
							shouldReportLeak = true
						} else {
							shouldReportRelease = true
						}
					} else if !hasFree {
						// No CFG to prove a leak path: fall back to the coarse
						// heuristic. A malloc whose result escapes at its site or is
						// returned anywhere is ownership-transferred, not leaked.
						if containsLine(escapeLines, allocLine) || len(transferLines) > 0 {
							shouldReportRelease = true
						} else {
							shouldReportLeak = true
						}
					} else {
						shouldReportRelease = true
					}

					// ML-12: a self-realloc p = realloc(p, n) immediately consuming
					// this allocation leaks the OLD block when realloc fails (returns
					// NULL), even if a later free(p) releases the NEW block. Force a
					// suspected leak instead of a release.
					for _, rl := range selfReallocLines {
						if rl <= allocLine {
							continue
						}
						immediate := true
						for _, fl := range freeLines {
							if fl > allocLine && fl < rl {
								immediate = false
								break
							}
						}
						if immediate {
							shouldReportLeak = true
							shouldReportRelease = false
							break
						}
					}

					if shouldReportLeak {
						// ML-01/18: a pointer with NO free/transfer/escape on any path is
						// DEFINITELY lost (hasLostResource proved a leak path AND there is
						// no releasing/handing-off node anywhere), so mark it so the
						// planner can confirm instead of leaving it suspected.
						definiteLeak := len(freeLines) == 0 && len(escapeLines) == 0 && len(transferLines) == 0
						props := map[string]string{
							"variable": varName,
							"origin":   "malloc",
						}
						if definiteLeak {
							props["definite"] = "true"
						}
						if emitEvent(ctx, d.store, d.logger, "MEMORY_ALLOC", f.ID, &db.Location{FileID: file.ID, Line: allocLine}, props) {
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
						// alloc_line ties this release to its specific allocation
						// site, so the planner's ReleaseFilter drops only the released
						// site and not a sibling alloc site that leaks.
						if emitEvent(ctx, d.store, d.logger, "MEMORY_RELEASE", f.ID, &db.Location{FileID: file.ID, Line: releaseLine}, map[string]any{
							"variable":   varName,
							"origin":     "free",
							"alloc_line": allocLine,
						}) {
							result.EventsCreated++
						}
					}

				}
			}
		}
	})
	return result, err
}

func (d *MemoryLeakDetector) findAllocations(ctx context.Context, f *db.Function, file *db.File, assigns, inits, calls []parser.Node) map[string][]int {
	allocs := make(map[string][]int)

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
			allocs[varName] = append(allocs[varName], node.StartLine())
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

	// Output-parameter allocators (`asprintf(&p, ...)`, `getline(&p, ...)`)
	// allocate into the addressed variable rather than returning it (ML-11).
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if name := outputParamAllocVar(call); name != "" {
			allocs[name] = append(allocs[name], call.StartLine())
		}
	}

	for name := range allocs {
		sort.Ints(allocs[name])
	}
	return allocs
}

// outputParamAllocVar returns the variable an output-parameter allocator writes:
// `asprintf(&p, ...)` / `getline(&p, ...)` / `getdelim(&p, ...)` allocate into p.
var outputParamAllocators = map[string]bool{
	"asprintf": true, "vasprintf": true, "getline": true, "getdelim": true,
}

func outputParamAllocVar(call parser.Node) string {
	if !outputParamAllocators[extractCallName(call)] {
		return ""
	}
	args := getCallArgs(call)
	if len(args) == 0 {
		return ""
	}
	target, ok := args[0].AddressTakenTarget()
	if !ok || target.Kind() != "identifier" {
		return ""
	}
	return target.Text()
}

func (d *MemoryLeakDetector) findFrees(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, macros map[string]macroFreeSummary, inits, assigns []parser.Node) map[string][]int {
	frees := make(map[string][]int)
	aliases := findAliases(f, inits, assigns)
	recordFree := func(name string, line int) {
		if name == "" {
			return
		}
		frees[name] = append(frees[name], line)
		// free(q) where q = p (whole-variable alias) releases p's block too, so
		// a leak of p is not reported (ML-05). A field alias (q = p->f) is not a
		// whole-variable alias, so terminalBaseVar stops there.
		if base := terminalBaseVar(aliases, name); base != name {
			frees[base] = append(frees[base], line)
		}
	}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		// A freeing function-like macro (free-only or free+null) releases its
		// first argument; the free inside the macro is invisible to tree-sitter.
		if s, ok := macros[callName]; ok && s.freesArg {
			if args := getCallArgs(call); len(args) > 0 {
				recordFree(argIdentifier(args[0]), call.StartLine())
			}
			continue
		}
		if !apikb.IsDeallocator(callName) {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() == "argument_list" {
				for _, arg := range child.NamedChildren() {
					recordFree(argIdentifier(arg), call.StartLine())
				}
			}
		}
	}
	return frees
}

// argIdentifier returns the bare identifier of a release-call argument, unwrapping
// cast and parenthesized expressions (`free((void *)p)` → "p", ML-06). A non-trivial
// expression (`free(p + i)`) is NOT unwrapped and returns "", because it does not
// release a single tracked variable.
func argIdentifier(arg parser.Node) string {
	switch arg.Kind() {
	case "identifier":
		return arg.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range arg.NamedChildren() {
			if id := argIdentifier(c); id != "" {
				return id
			}
		}
	}
	return ""
}

// unwrapCastParen unwraps cast/parenthesized wrappers to the wrapped VALUE
// (`(T *)p` → p, `((p->f))` → p->f). The value is the last named child of a
// cast (its operand) and the single child of a parenthesized expression.
func unwrapCastParen(node parser.Node) parser.Node {
	for node.Kind() == "cast_expression" || node.Kind() == "parenthesized_expression" {
		kids := node.NamedChildren()
		if len(kids) == 0 {
			return node
		}
		node = kids[len(kids)-1]
	}
	return node
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
	if varName == "" {
		return false
	}
	// AST-based null-check (word-boundary safe, ML-08): the condition establishes
	// varName as NULL/zero when it evaluates TRUE — `!p`, `p == NULL`, `p == 0`,
	// `NULL == p`, `0 == p`, and the assignment-in-condition `(p = malloc()) ==
	// NULL`. The previous strings.Contains matched `!ptr` against varName `p`
	// (the "!p" substring) and misread a `return p` transfer as a null-guard.
	for _, v := range parser.NullCheckedVars(*cond) {
		if v == varName {
			return true
		}
	}
	return false
}

// hasLostResource reports whether the allocation at allocLine is lost: there is
// a control-flow path from it to the function exit OR to a LATER write to the
// same variable (an overwrite that drops the previous pointer — the classic
// `p = malloc(); p = malloc();` double-allocation) without passing a free, a
// null-guard early return, an escape, or a return of the pointer itself
// (transferLines — `return p` hands ownership to the caller on that path only).
// It uses the statement-level CFG so flat functions (an `if` with an expression
// body) no longer degenerate to a path-insensitive fallback. The overwrite
// targets catch a lost allocation even when a later pointer is freed
// (`p = malloc(); p = malloc(); free(p);` leaks the first block).
func hasLostResource(cfg *graph.StmtCFG, allocLine int, freeLines []int, nullGuardReturns []int, escapeLines []int, transferLines []int, overwriteLines []int) bool {
	if cfg == nil {
		return false
	}
	allocNode := cfg.NodeAt(allocLine)
	if allocNode == nil {
		return true // cannot prove non-leak; report conservatively
	}
	avoid := make(map[int]bool, len(freeLines)+len(nullGuardReturns)+len(escapeLines)+len(transferLines))
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
	for _, l := range transferLines {
		if n := cfg.NodeAt(l); n != nil {
			avoid[n.ID] = true
		}
	}
	if cfg.ReachesAvoiding(allocNode.ID, avoid, cfg.Exit) {
		return true
	}
	for _, w := range overwriteLines {
		if w <= allocLine {
			continue
		}
		if n := cfg.NodeAt(w); n != nil && cfg.ReachesAvoiding(allocNode.ID, avoid, n.ID) {
			return true
		}
	}
	return false
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

		if argIdentifier(rhs) == varName {
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
		//
		// ML-14 tradeoff: this errs toward NO false positive for the common
		// caller-owned-field idiom. If a caller stores into the field but never
		// frees it, that leak is intra-procedurally invisible here — resolving
		// it requires interprocedural evidence that the field is (not) released
		// somewhere in the call graph, which is beyond the detector's scope.
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
		// An `extern` declaration (`extern int *g;`) names an external object, not
		// a local: storing p into it escapes ownership (ML-09). The previous code
		// collected every in-function declaration as local, so `g = p` for an
		// extern-declared global was misread as a local store and reported as a
		// leak.
		isExtern := false
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "storage_class_specifier" && child.Text() == "extern" {
				isExtern = true
			}
		}
		if isExtern {
			continue
		}
		for _, child := range decl.NamedChildren() {
			name := declaredIdentifier(child)
			if name != "" && !parser.IsCTypeKeyword(name) {
				locals[name] = true
			}
		}
	}
	return locals
}

// declaredIdentifier returns the identifier a declaration child binds, descending
// pointer/array/function/parenthesized declarator wrappers (`char *p` -> "p").
// It returns "" for type-position nodes and for the initializer value, so a type
// spelling or an initializer expression is never mistaken for a local. Without
// this descent a pointer local (`char *p;` then `p = malloc()` on a later line)
// is not recognized as local, and findEscapeLines misreads the assignment as an
// escape-to-global — a silent false-negative leak.
func declaredIdentifier(node parser.Node) string {
	switch node.Kind() {
	case "identifier":
		return node.Text()
	case "pointer_declarator", "array_declarator", "function_declarator",
		"parenthesized_declarator", "init_declarator":
		for _, child := range node.NamedChildren() {
			if name := declaredIdentifier(child); name != "" {
				return name
			}
		}
	}
	return ""
}

// writeLinesFor returns, in source order, the lines where varName is the full
// left-hand side of an assignment/initializer — a write that REPLACES its value
// (`p = malloc()`, `p = q`, `p = NULL`). `p = realloc(p, n)` is excluded: it
// consumes the previous allocation rather than dropping it. A later write is an
// "overwrite": reaching one without a free in between means the previous
// allocation's pointer was lost.
func writeLinesFor(assigns, inits []parser.Node, f *db.Function, varName string) []int {
	var lines []int
	check := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs, rhs := children[0], children[1]
		if lhs.Kind() != "identifier" || lhs.Text() != varName {
			return
		}
		if isReallocOf(rhs, varName) {
			return
		}
		lines = append(lines, node.StartLine())
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			check(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			check(i)
		}
	}
	sort.Ints(lines)
	return lines
}

// isReallocOf reports whether expr is `realloc(varName, ...)` (possibly cast or
// parenthesized).
func isReallocOf(expr parser.Node, varName string) bool {
	for expr.Kind() == "cast_expression" || expr.Kind() == "parenthesized_expression" {
		children := expr.NamedChildren()
		if len(children) == 0 {
			return false
		}
		expr = children[0]
	}
	if expr.Kind() != "call_expression" || extractCallName(expr) != "realloc" {
		return false
	}
	args := getCallArgs(expr)
	if len(args) == 0 {
		return false
	}
	return args[0].Kind() == "identifier" && args[0].Text() == varName
}

// lhsPlainVar returns the variable a direct-write LHS names: "p" for `p = ...`
// and for a declarator `*p = ...` / `int *p = ...`, and "" for a field/subscript
// write (`p->f = ...`). It distinguishes a whole-variable write from a member
// write, which matters for self-realloc detection (a `p->f = realloc(p, n)` is
// NOT a self-realloc of p).
func lhsPlainVar(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		return lhs.Text()
	case "pointer_declarator", "array_declarator", "function_declarator", "parenthesized_declarator":
		return extractVarName(lhs)
	}
	return ""
}

// findReallocConsumeLines returns the lines where realloc(varName, n) moves
// varName's block into a DIFFERENT target (`tmp = realloc(p, n)`). The old block
// is consumed on success and still reachable through p on failure, so p is not
// leaked either way — model it as a release at that line so the leak analysis
// does not report p (a realloc-into-temp is not a lost pointer).
func findReallocConsumeLines(assigns, inits []parser.Node, f *db.Function, varName string) []int {
	var lines []int
	check := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs, rhs := children[0], children[1]
		if !isReallocOf(rhs, varName) {
			return
		}
		if lhsPlainVar(lhs) == varName {
			return // self-realloc, not a plain consume
		}
		lines = append(lines, node.StartLine())
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			check(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			check(i)
		}
	}
	return lines
}

// findSelfReallocLines returns the lines where varName is realloc'd into itself
// (`p = realloc(p, n)`). On realloc failure the OLD block leaks (the pointer is
// overwritten with NULL), the classic CWE-401 form (ML-12).
func findSelfReallocLines(assigns, inits []parser.Node, f *db.Function, varName string) []int {
	var lines []int
	check := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs, rhs := children[0], children[1]
		if lhsPlainVar(lhs) != varName {
			return
		}
		if isReallocOf(rhs, varName) {
			lines = append(lines, node.StartLine())
		}
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			check(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			check(i)
		}
	}
	return lines
}

// isMallocExpr reports whether expr is (or casts) a malloc/calloc/realloc call.
// Nested casts (`(int)(size_t)malloc(64)`) are unwrapped recursively. The
// implicit result-returning allocators (strdup/getcwd/...) are recognized via
// apikb.IsAllocator, and realpath(path, NULL) — which allocates only when its
// second argument is NULL — is recognized explicitly (ML-11).
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
	name := extractCallName(expr)
	if apikb.IsAllocator(name) {
		return true
	}
	if name == "realpath" {
		args := getCallArgs(expr)
		return len(args) >= 2 && parser.IsNullOperand(args[1])
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

// findReturnVarLines returns the lines of return statements that hand varName to
// the caller (bare `return p` or one level of parentheses `return (p)`). These
// are transfer points, not leak points; they are fed to hasLostResource's avoid
// set so the path-sensitive analysis distinguishes a return on ONE path from a
// leak on ANOTHER.
func findReturnVarLines(varName string, returns []parser.Node, f *db.Function) []int {
	var lines []int
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		if returnReturnsVar(ret, varName) {
			lines = append(lines, ret.StartLine())
		}
	}
	return lines
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
