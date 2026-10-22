package evidence

import (
	"context"
	"sort"
	"strconv"
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

	// Wrapper functions that return an allocator result (the "封装成函数"
	// production pattern) are allocation sites even with a custom name. Computed
	// once for the whole codebase, not per file.
	allocReturns, borrowFuncs, err := allocatorReturnFuncs(ctx, d.store, d.parser, d.logger)
	if err != nil {
		return result, err
	}
	// Cross-file typedef resolution: a `typedef int Status; Status st = ...` must
	// count as a scalar status code, not an allocation (EL-06).
	globalTypedefs := buildGlobalTypedefs(ctx, d.store, d.parser)

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		decls := root.FindAll("declaration")
		ifs := root.FindAll("if_statement")
		macros := macroFreeSummaries(root)
		typedefs := globalTypedefs.clone()
		typedefs.addRoot(root)

		for _, f := range fileFuncs {
			localVars := findLocalVarsFrom(decls, f)
			scalarVars := findScalarVarsFrom(decls, f, typedefs)
			allocs := d.findAllocations(ctx, f, file, assigns, inits, calls, allocReturns, borrowFuncs, scalarVars)
			frees := d.findFrees(ctx, f, file, calls, macros, inits, assigns)
			returnLines := findReturnLinesFrom(returns, f)

			body := bodies[f.StartLine]
			cfg := graph.BuildStmtCFG(body, f.EndLine)
			cfgValid := body.Kind() == "compound_statement"
			// The set of variables this function allocates. A pointer stored
			// through one of them (`*container = buf`) points INTO the heap, not
			// the stack, so its content escapes with the container's ownership
			// rather than leaking on its own (see findEscapeLines' pointer case).
			allocVarNames := make(map[string]bool, len(allocs))
			for name := range allocs {
				allocVarNames[name] = true
			}

			for varName, allocLines := range allocs {
				allFreeCalls := frees[varName]
				// realloc into a DIFFERENT target (`tmp = realloc(p, n)`) consumes
				// p's block on success and leaves p reachable on failure, so p is
				// never leaked by that call — model it as a release at the realloc
				// line so p is not reported.
				for _, l := range findReallocConsumeLines(assigns, inits, f, varName) {
					allFreeCalls = append(allFreeCalls, freeCall{line: l, api: "realloc"})
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
				// Early returns guarded by a FAILED output-param allocator check
				// (`if (asprintf(&p, ...) < 0) return;`) are not leak evidence for
				// the out-param variable: the allocation never happened on that
				// branch (docs §5.3 success-branch binding).
				nullGuardReturns = append(nullGuardReturns, findAllocGuardedReturns(ifs, returns, assigns, inits, f, varName)...)
				escapeLinesAll := findEscapeLines(assigns, calls, returns, f, varName, localVars, allocVarNames, allocReturns, true)
				overwriteLines := writeLinesFor(assigns, inits, f, varName)

				for _, allocLine := range allocLines {
					allocAPI := callNameAtLine(calls, allocLine)
					// Family pairing (docs §6): an object allocated by a modeled
					// API is validly released only by its ValidFrees (plus generic
					// releases where the model allows). A mismatched releaser —
					// xmlXPathFreeContext on an XPath object, free() on an XPath
					// context, cJSON_Delete on strdup's block — does NOT count as a
					// release; the allocation leaks and the mismatch is surfaced in
					// the event props for the AI.
					effectiveCalls, hasFree, mismatchedCalls := effectiveFreeCalls(allFreeCalls, allocAPI)
					freeLines := freeCallLines(effectiveCalls)
					// Conditional ownership transfer (docs §5.2C): a modeled
					// TransferOnSuccess call guarded by its own return value with
					// no failure-branch release is NOT an unconditional escape —
					// the failure path still owns (and leaks) the object.
					escapeLines, conditionalTransfers := splitConditionalEscapes(escapeLinesAll, calls, ifs, freeLines)
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
						// Extended: even when free/escape/transfer lines exist, if none
						// is structurally reachable from the allocation in the CFG (dead
						// code after an unconditional return/goto), the leak is still
						// definite — the release can never execute. A conditional
						// transfer is a channel that exists (the success branch hands
						// the object off), so it keeps the guarded-failure leak
						// suspected for the AI rather than definite.
						definiteLeak := len(freeLines) == 0 && len(escapeLines) == 0 && len(conditionalTransfers) == 0 && len(transferLines) == 0
						if !definiteLeak && cfgValid && !canReachAnyRelease(cfg, allocLine, freeLines, append(append([]int{}, escapeLines...), conditionalTransfers...), transferLines) {
							definiteLeak = true
						}
						props := map[string]string{
							"variable":    varName,
							"origin":      "malloc",
							"api":         allocAPI,
							"escape_kind": leakEscapeKind(escapeLines, transferLines),
						}
						if len(freeLines) > 0 {
							props["free_lines"] = joinIntLines(freeLines)
						}
						if len(conditionalTransfers) > 0 {
							props["transfer_conditional"] = joinCallLines(calls, conditionalTransfers)
						}
						if len(mismatchedCalls) > 0 {
							props["free_mismatch"] = joinFreeCalls(mismatchedCalls)
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
							"api":      allocAPI,
						}) {
							result.EventsCreated++
						}
						releaseLine := allocLine
						freeAPI := allocAPI
						if len(effectiveCalls) > 0 {
							releaseLine = effectiveCalls[0].line
							freeAPI = effectiveCalls[0].api
						}
						// alloc_line ties this release to its specific allocation
						// site, so the planner's ReleaseFilter drops only the released
						// site and not a sibling alloc site that leaks.
						if emitEvent(ctx, d.store, d.logger, "MEMORY_RELEASE", f.ID, &db.Location{FileID: file.ID, Line: releaseLine}, map[string]any{
							"variable":   varName,
							"origin":     "free",
							"alloc_line": allocLine,
							"free_api":   freeAPI,
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

func (d *MemoryLeakDetector) findAllocations(ctx context.Context, f *db.Function, file *db.File, assigns, inits, calls []parser.Node, allocReturns, borrowFuncs map[string]bool, scalarVars map[string]bool) map[string][]int {
	allocs := make(map[string][]int)

	checkNode := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		// A compound assignment (`ret += foo_new(...)`) is arithmetic, not an
		// allocation store — an allocator result is always assigned with `=`.
		// Without this guard, `ret += CLI_NewDefineCmdElement(...)` produces a
		// spurious MEMORY_ALLOC for the integer `ret` when `_new` triggers the
		// zero-config allocator heuristic, leading to a confirmed false positive.
		if node.Kind() == "assignment_expression" {
			if op := node.ChildByFieldName("operator"); op != nil && op.Text() != "=" {
				return
			}
		}
		// A get-or-create-and-cache BORROW (`x = get_or_create(...)` whose callee
		// caches the pointer into a global before returning) is NOT an allocation
		// site for the caller, even when the callee name matches the zero-config
		// `_new`/`_alloc` heuristic (nlog_db_create_new_ctrl_item). The caller
		// receives a reference the global owns; freeing it would double-free.
		if isBorrowCall(rhs, borrowFuncs) {
			return
		}
		// Only a real malloc/calloc/realloc CALL on the right-hand side is an
		// allocation. A substring match would treat `strm->zalloc = zcalloc`
		// (assigning an allocator function pointer) as an allocation because
		// "zcalloc" contains "calloc".
		if !isMallocExpr(rhs, allocReturns) {
			return
		}
		varName := ""
		if lhs.Kind() == "identifier" {
			varName = lhs.Text()
			// A whole-variable store to a SCALAR local (bool/int/uint32_t/...)
			// is a status-code assignment, not a heap allocation, even when the
			// callee name triggers the zero-config allocator heuristic (`_new`,
			// `remalloc`, `*_alloc`). Only a pointer-typed target can hold an
			// allocation; a known-scalar local is skipped. Typedef'd pointer
			// types (`MsgPdu p` = `char **p`) are NOT in scalarVars, so they
			// stay candidates (fail-open) — never a silent false negative.
			if scalarVars[varName] {
				return
			}
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

// outputParamAllocVar returns the variable an output-parameter allocator
// writes: `asprintf(&p, ...)` / `getline(&p, ...)` allocate into p. The
// allocator set and the char** argument index come from the ExternalAPIs
// model (apikb.IsOutParamAllocator), so third-party out-param allocators
// are added in one place instead of a detector-local hardcoded table.
func outputParamAllocVar(call parser.Node) string {
	idx, ok := apikb.IsOutParamAllocator(extractCallName(call))
	if !ok {
		return ""
	}
	args := getCallArgs(call)
	if idx >= len(args) {
		return ""
	}
	target, ok := args[idx].AddressTakenTarget()
	if !ok || target.Kind() != "identifier" {
		return ""
	}
	return target.Text()
}

// freeCall is one release site: the line and the release API name. Carrying
// the API lets the detector validate the allocator↔deallocator family
// pairing (docs §6): xmlXPathEvalExpression's object must be released by
// xmlXPathFreeObject, not by xmlXPathFreeContext or free().
type freeCall struct {
	line int
	api  string
}

func (d *MemoryLeakDetector) findFrees(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, macros map[string]macroFreeSummary, inits, assigns []parser.Node) map[string][]freeCall {
	frees := make(map[string][]freeCall)
	aliases := findAliases(f, inits, assigns)
	recordFree := func(name string, line int, api string) {
		if name == "" {
			return
		}
		frees[name] = append(frees[name], freeCall{line: line, api: api})
		// free(q) where q = p (whole-variable alias) releases p's block too, so
		// a leak of p is not reported (ML-05). A field alias (q = p->f) is not a
		// whole-variable alias, so terminalBaseVar stops there.
		if base := terminalBaseVar(aliases, name); base != name {
			frees[base] = append(frees[base], freeCall{line: line, api: api})
		}
	}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		// A freeing function-like macro (free-only or free+null) releases its
		// first argument; the free inside the macro is invisible to tree-sitter.
		// The macro's release API is recorded as "free" — freesArg is only set
		// when the macro body calls free(param) itself.
		if s, ok := macros[callName]; ok && s.freesArg {
			if args := getCallArgs(call); len(args) > 0 {
				recordFree(argIdentifier(args[0]), call.StartLine(), "free")
			}
			continue
		}
		if !apikb.IsDeallocator(callName) {
			continue
		}
		if args := getCallArgs(call); len(args) > 0 {
			recordFree(argIdentifier(args[0]), call.StartLine(), callName)
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
	case "pointer_expression":
		if strings.HasPrefix(strings.TrimSpace(arg.Text()), "*") {
			for _, c := range arg.NamedChildren() {
				if id := argIdentifier(c); id != "" {
					return id
				}
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
// callNameAtLine returns the callee name of the call expression at line, so
// leak events can carry the concrete acquire API (malloc/fopen/socket)
// alongside the line the analyzer already matched.
func callNameAtLine(calls []parser.Node, line int) string {
	for _, call := range calls {
		if call.StartLine() == line {
			return extractCallName(call)
		}
	}
	return ""
}

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

// canReachAnyRelease reports whether any free/escape/transfer line is
// structurally reachable from the allocation at allocLine in the CFG. It
// returns false when every releasing/handing-off line is dead code (after an
// unconditional return or goto), meaning the allocation can never be released
// — a definite leak even though freeLines/escapeLines/transferLines are
// non-empty. This is a may-analysis: a true result means "a release is
// reachable" (so the leak is conditional, not definite); a false result means
// "no release is reachable" (so the leak is definite). It is conservative in
// the safe direction — if the CFG lacks precision (e.g. cannot model a
// computed goto), it may return true (reachable) and leave the candidate
// suspected, never falsely confirming.
func canReachAnyRelease(cfg *graph.StmtCFG, allocLine int, freeLines, escapeLines, transferLines []int) bool {
	allocNode := cfg.NodeAt(allocLine)
	if allocNode == nil {
		return false
	}
	for _, lines := range [][]int{freeLines, escapeLines, transferLines} {
		for _, l := range lines {
			if l == allocLine {
				continue
			}
			if n := cfg.NodeAt(l); n != nil && cfg.Reaches(allocNode.ID, n.ID) {
				return true
			}
		}
	}
	return false
}

// findEscapeLines returns the lines where varName's allocation "escapes" the
// function: it is stored into a subscript/field, assigned to an identifier
// that is not a local of the function (a global/static), or stored through a
// dereferenced pointer whose base is itself a heap allocation (`*container =
// p` where container = malloc(...) and the container itself escapes). A value
// that escapes is transferred ownership, not leaked.
//
// useEscapeFuncs gates the naming-heuristic escape-function branch: full leak
// detection uses it, but the getter-borrow classifier (allocatorReturnFuncs)
// passes false so a wrapper that merely logs/stores its result via a
// `_add`/`_store`-named helper is not misread as a borrow.
// leakEscapeKind summarizes the ownership-release channels a leak event's
// variable has (shared by the memory- and resource-leak detectors): "return"
// when the value is returned to the caller somewhere, "store" when it is
// stored into a non-local (global/parameter/container), "none" when no
// channel exists. The planner surfaces it as the escape@ hint token so the
// classifier can tell "no channel at all" (machine-proved loss) from "a
// channel exists but the CFG proved a leak path bypasses it".
func leakEscapeKind(escapeLines, transferLines []int) string {
	if len(transferLines) > 0 {
		return "return"
	}
	if len(escapeLines) > 0 {
		return "store"
	}
	return "none"
}

func joinIntLines(lines []int) string {
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = strconv.Itoa(l)
	}
	return strings.Join(parts, ",")
}

// freeCallLines extracts the bare line numbers of a freeCall slice.
func freeCallLines(calls []freeCall) []int {
	lines := make([]int, len(calls))
	for i, c := range calls {
		lines[i] = c.line
	}
	return lines
}

// effectiveFreeCalls filters a variable's release sites against the family
// policy of the specific allocation API (docs §6). For an unmodeled
// allocator every deallocator counts — the pre-model behavior. For a
// modeled one, only the policy's ValidFrees (plus generic releases when
// allowed) release the object; mismatched releasers are returned separately
// so the leak event can surface them as evidence for the AI.
func effectiveFreeCalls(all []freeCall, allocAPI string) (effective []freeCall, hasFree bool, mismatched []freeCall) {
	policy := apikb.AllocatorReleasePolicy(allocAPI)
	for _, fc := range all {
		if policy.Releases(fc.api) {
			effective = append(effective, fc)
		} else {
			mismatched = append(mismatched, fc)
		}
	}
	return effective, len(effective) > 0, mismatched
}

// joinFreeCalls renders mismatched releasers as "api:line,api:line" for the
// leak event's free_mismatch prop.
func joinFreeCalls(calls []freeCall) string {
	parts := make([]string, len(calls))
	for i, c := range calls {
		parts[i] = c.api + ":" + strconv.Itoa(c.line)
	}
	return strings.Join(parts, ",")
}

// joinCallLines renders conditional transfer sites as "api:line,..." for the
// leak event's transfer_conditional prop.
func joinCallLines(calls []parser.Node, lines []int) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		parts = append(parts, callNameAtLine(calls, l)+":"+strconv.Itoa(l))
	}
	return strings.Join(parts, ",")
}

// splitConditionalEscapes separates conditional ownership transfers from
// unconditional escapes (docs §5.2C). A modeled TransferOnSuccess call whose
// result is guarded by the call's own return value (`if (!cJSON_AddItemToObject(...))`)
// transfers only on the success branch: with NO failure-branch release to
// fall back on, the transfer must not suppress the leak — the failure path
// still owns (and leaks) the object. The line moves to conditional, which
// counts as "a channel exists" for the definite-leak decision (staying
// suspected for the AI) but never enters the hasLostResource avoid set.
// When a release exists anywhere, both branches are covered and the full
// escape stands.
func splitConditionalEscapes(escapeLines []int, calls []parser.Node, ifs []parser.Node, freeLines []int) (unconditional, conditional []int) {
	if len(freeLines) > 0 {
		return escapeLines, nil
	}
	guardedLines := make(map[int]bool, len(ifs))
	for _, ifStmt := range ifs {
		guardedLines[ifStmt.StartLine()] = true
	}
	for _, l := range escapeLines {
		kind, _, modeled := apikb.EscapeOwnership(callNameAtLine(calls, l))
		if modeled && kind == apikb.OwnershipTransferOnSuccess && guardedLines[l] {
			conditional = append(conditional, l)
			continue
		}
		unconditional = append(unconditional, l)
	}
	return unconditional, conditional
}

// findAllocGuardedReturns returns the return lines guarded by a FAILED
// output-parameter allocator check, for one out-param variable (docs §5.3):
// `if (asprintf(&p, ...) < 0) return;` and the assigned-status form
// `ret = asprintf(&p, ...); if (ret < 0) return;`. On the failing branch the
// allocation never happened, so the early return is not leak evidence.
// The failure comparison is deliberately narrow — `< 0`-style strict
// comparisons and equality against negative literals only: asprintf/getline
// return non-negative counts or -1, so `== 0`/`<= 0` can denote SUCCESS
// (empty output) and would misclassify the branch.
func findAllocGuardedReturns(ifs, returns, assigns, inits []parser.Node, f *db.Function, varName string) []int {
	if varName == "" {
		return nil
	}
	// A status variable is either assigned (`ret = asprintf(&p, ...)`) or
	// declared-with-initializer (`int ret = asprintf(&p, ...)`) from the
	// out-param allocator call for varName.
	statusVars := map[string]bool{}
	recordStatus := func(lhs, rhs parser.Node) {
		if lhs.Kind() != "identifier" && lhs.Kind() != "pointer_declarator" && lhs.Kind() != "init_declarator" {
			return
		}
		name := assignedVariable(lhs)
		if name == "" {
			return
		}
		if rhs.Kind() == "parenthesized_expression" || rhs.Kind() == "cast_expression" {
			for _, c := range rhs.NamedChildren() {
				rhs = c
				break
			}
		}
		if rhs.Kind() != "call_expression" {
			return
		}
		idx, ok := apikb.IsOutParamAllocator(extractCallName(rhs))
		if !ok {
			return
		}
		args := getCallArgs(rhs)
		if idx >= len(args) {
			return
		}
		target, ok := args[idx].AddressTakenTarget()
		if !ok || target.Kind() != "identifier" || target.Text() != varName {
			return
		}
		statusVars[name] = true
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		recordStatus(children[0], children[1])
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		children := init.NamedChildren()
		if len(children) < 2 {
			continue
		}
		recordStatus(children[0], children[1])
	}
	var lines []int
	for _, ifStmt := range ifs {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil || !isOutParamAllocFailureGuard(*cond, varName, statusVars) {
			continue
		}
		consequence := ifStmt.ChildByFieldName("consequence")
		if consequence == nil {
			continue
		}
		for _, ret := range consequence.FindAll("return_statement") {
			lines = append(lines, ret.StartLine())
		}
	}
	return lines
}

// isOutParamAllocFailureGuard reports whether an if condition tests the
// FAILURE of an out-param allocation for varName, either directly
// (`asprintf(&p, ...) < 0`) or through a status variable assigned from the
// call (`ret = asprintf(&p, ...); if (ret < 0)`).
func isOutParamAllocFailureGuard(cond parser.Node, varName string, statusVars map[string]bool) bool {
	for _, bin := range cond.FindAll("binary_expression") {
		lhs, rhs, op := binaryOperands(bin)
		if op != "<" && op != "==" && op != "!=" {
			continue
		}
		callSide, otherSide := lhs, rhs
		if callSide.Kind() != "call_expression" && rhs.Kind() == "call_expression" {
			callSide, otherSide = rhs, lhs
		}
		if callSide.Kind() != "call_expression" {
			// The assigned-status form: one side is the status variable.
			idSide, numSide := lhs, rhs
			if idSide.Kind() != "identifier" && rhs.Kind() == "identifier" {
				idSide, numSide = rhs, lhs
			}
			if idSide.Kind() != "identifier" || !statusVars[idSide.Text()] {
				continue
			}
			if !isFailureLiteral(numSide, op) {
				continue
			}
			return true
		}
		idx, ok := apikb.IsOutParamAllocator(extractCallName(callSide))
		if !ok {
			continue
		}
		args := getCallArgs(callSide)
		if idx >= len(args) {
			continue
		}
		target, ok := args[idx].AddressTakenTarget()
		if !ok || target.Kind() != "identifier" || target.Text() != varName {
			continue
		}
		if !isFailureLiteral(otherSide, op) {
			continue
		}
		return true
	}
	return false
}

// binaryOperands returns a binary expression's left/right operands and the
// operator text. tree-sitter exposes the operator as an anonymous token, so
// it is reachable only through the operator field, not NamedChildren.
func binaryOperands(bin parser.Node) (parser.Node, parser.Node, string) {
	op := ""
	if o := bin.ChildByFieldName("operator"); o != nil {
		op = strings.TrimSpace(o.Text())
	}
	lhs, rhs := parser.Node{}, parser.Node{}
	if l := bin.ChildByFieldName("left"); l != nil {
		lhs = *l
	}
	if r := bin.ChildByFieldName("right"); r != nil {
		rhs = *r
	}
	return lhs, rhs, op
}

// isFailureLiteral reports whether the compared operand denotes the FAILURE
// value of an out-param allocator's status result: strictly negative for
// `<`, or a negative literal for `==` (e.g. -1). A bare 0 is rejected for
// `==` (an empty successful output) and `!=` is only accepted against a
// negative literal for symmetry.
func isFailureLiteral(side parser.Node, op string) bool {
	node := side
	if node.Kind() == "" {
		return false
	}
	if node.Kind() == "parenthesized_expression" {
		kids := node.NamedChildren()
		if len(kids) == 1 {
			node = kids[0]
		}
	}
	switch node.Kind() {
	case "number_literal":
		neg := strings.HasPrefix(strings.TrimSpace(node.Text()), "-")
		if op == "<" {
			// `< 0` (and any negative bound): failure for a non-negative-or
			// -1 status domain.
			return true
		}
		return neg
	case "unary_expression":
		// `-1` spelled as unary minus.
		return op == "==" || op == "!=" || op == "<"
	}
	return false
}

func findEscapeLines(assigns, calls, returns []parser.Node, f *db.Function, varName string, localVars map[string]bool, allocVarNames map[string]bool, allocReturns map[string]bool, useEscapeFuncs bool) []int {
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
			} else if lhs.Kind() == "pointer_expression" {
				base := ""
				for _, child := range lhs.NamedChildren() {
					if child.Kind() == "identifier" {
						base = child.Text()
						break
					}
				}
				// Escape through a non-local (parameter/global) base: the stored
				// pointer's ownership rides with that object, not the function's
				// frame. A base that is itself a heap allocation (`*container = p`)
				// escapes p only when the container ITSELF escapes (returned or
				// stored to a non-local); a container that is only freed at the end
				// does NOT free its members, so p still leaks (EL-01).
				if base == "" {
					continue
				}
				if !localVars[base] {
					lines = append(lines, assign.StartLine())
				} else if allocVarNames[base] && containerEscapes(assigns, calls, returns, f, base, localVars) {
					lines = append(lines, assign.StartLine())
				}
			} else if lhs.Kind() == "identifier" && !localVars[lhs.Text()] {
				lines = append(lines, assign.StartLine())
			}
		}
		// A malloc whose result is assigned directly to a non-local identifier
		// (`g = malloc()`) escapes at the allocation site itself.
		if lhs.Kind() == "identifier" && lhs.Text() == varName && !localVars[varName] && isMallocExpr(rhs, allocReturns) {
			lines = append(lines, assign.StartLine())
		}
		// A malloc assigned through a dereferenced non-local pointer
		// (`*root = malloc(...)`) escapes at the allocation site: the
		// caller owns the pointed-to object via the output parameter and
		// frees it elsewhere. A local base (`*local = malloc(...)`) still
		// leaks if never freed.
		if lhs.Kind() == "pointer_expression" && isMallocExpr(rhs, allocReturns) {
			base := ""
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					base = child.Text()
					break
				}
			}
			if base != "" && base == varName && !localVars[base] {
				lines = append(lines, assign.StartLine())
			}
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
		if (lhs.Kind() == "field_expression" || lhs.Kind() == "subscript_expression") && isMallocExpr(rhs, allocReturns) {
			base := ""
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					base = child.Text()
					break
				}
			}
			// Only the tracked variable's own field store escapes it; an unrelated
			// `global->field = malloc()` must not suppress the leak of a different
			// local (`char *p = malloc(10); g->buf = malloc(20);`).
			if base != "" && base == varName && !localVars[base] {
				lines = append(lines, assign.StartLine())
			}
		}
	}
	if useEscapeFuncs {
		for _, call := range calls {
			if !funcLineRange(f, call.StartLine()) {
				continue
			}
			callName := extractCallName(call)
			if !apikb.IsEscapeFunction(callName) {
				continue
			}
			// Modeled transfers escape through the modeled argument only
			// (cJSON_AddItemToObject takes the item as arg 2, xmlAddChild as
			// arg 1 — the parent argument must not be dragged in). Unmodeled
			// escape-shaped helpers keep the any-argument match.
			_, argIdx, modeled := apikb.EscapeOwnership(callName)
			args := getCallArgs(call)
			matched := false
			if modeled {
				if argIdx < len(args) && argIdentifier(args[argIdx]) == varName {
					matched = true
				}
			} else {
				for _, arg := range args {
					if argIdentifier(arg) == varName {
						matched = true
						break
					}
				}
			}
			if matched {
				lines = append(lines, call.StartLine())
			}
		}
	}
	return lines
}

// containerEscapes reports whether a heap-allocated container variable escapes
// the function — returned to the caller, stored to a non-local identifier or
// field/subscript, or handed to an escape function — so a pointer stored through
// it (`*container = p`) escapes with the container's ownership rather than
// leaking on its own. A container that is merely freed at the end
// (`*c = p; free(c);`) does NOT free its members, so it does not escape p.
func containerEscapes(assigns, calls, returns []parser.Node, f *db.Function, base string, localVars map[string]bool) bool {
	if len(findReturnVarLines(base, returns, f)) > 0 {
		return true
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs, rhs := children[0], children[1]
		if argIdentifier(rhs) != base {
			continue
		}
		switch lhs.Kind() {
		case "identifier":
			if !localVars[lhs.Text()] {
				return true
			}
		case "field_expression", "subscript_expression":
			b := ""
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					b = child.Text()
					break
				}
			}
			if b != "" && !localVars[b] {
				return true
			}
		}
	}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if !apikb.IsEscapeFunction(extractCallName(call)) {
			continue
		}
		for _, arg := range getCallArgs(call) {
			if argIdentifier(arg) == base {
				return true
			}
		}
	}
	return false
}

// findLocalVars returns the names of variables declared inside the function.
func findLocalVarsFrom(decls []parser.Node, f *db.Function) map[string]bool {
	locals := make(map[string]bool)
	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		// An `extern` declaration (`extern int *g;`) names an external object, and
		// a `static` local has static storage duration — both live outside the
		// call's lifetime, so a pointer stored into them escapes ownership rather
		// than leaking (ML-09 extended to the static-cache idiom, e.g.
		// `static iconv_t g; g = iconv_open(...)`). The previous code collected
		// every in-function declaration as local, so `g = p` for an extern/static
		// object was misread as a local store and reported as a leak.
		hasStaticStorage := false
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "storage_class_specifier" {
				if child.Text() == "extern" || child.Text() == "static" {
					hasStaticStorage = true
				}
			}
		}
		if hasStaticStorage {
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

// findScalarVarsFrom maps a local variable name to true when it is declared with
// a CERTAINLY-SCALAR builtin type (`bool`, `int`, `uint32_t`, `unsigned`, ...):
// a whole-variable store to it (`ret = foo_new(...)`) is a status-code assignment,
// not a heap allocation, even when the callee name triggers the zero-config
// allocator heuristic (`_new`, `remalloc`, `*_alloc`) — the dominant class of
// confirmed false positives on production repos (nlog/stat-registry accessors).
//
// A typedef'd base type (`MsgPdu p` where `MsgPdu = char **`) hides its
// pointer-ness inside the typedef, so it is NOT recorded here: the caller
// fail-opens and keeps the store as a candidate rather than silently dropping a
// real leak. Only a `primitive_type`/`sized_type_specifier` base — or a
// typedef that resolves to one (`typedef int Status`) — is treated as
// certainly-scalar; a pointer declarator (`T *p`) is never scalar. A name
// declared as a pointer anywhere in the function is dropped (block shadowing
// `int ret; { char *ret = malloc(); }`).
func findScalarVarsFrom(decls []parser.Node, f *db.Function, typedefs *typedefs) map[string]bool {
	scalars := make(map[string]bool)
	pointers := make(map[string]bool)
	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		if hasStaticStorageSpecifier(decl) {
			continue
		}
		baseScalar := hasScalarBaseType(decl, typedefs)
		for _, child := range decl.NamedChildren() {
			var declarator parser.Node
			switch child.Kind() {
			case "init_declarator":
				d := child.ChildByFieldName("declarator")
				if d == nil {
					continue
				}
				declarator = *d
			case "identifier", "pointer_declarator", "array_declarator",
				"function_declarator", "parenthesized_declarator":
				declarator = child
			default:
				continue // attribute / type-position node
			}
			name := declaredIdentifier(declarator)
			if name == "" {
				continue
			}
			if declaratorHasPointer(declarator) {
				pointers[name] = true
				continue
			}
			if baseScalar {
				scalars[name] = true
			}
		}
	}
	for name := range pointers {
		delete(scalars, name)
	}
	return scalars
}

// hasStaticStorageSpecifier reports whether a declaration carries extern/static,
// so its object has static storage duration (a pointer stored into it escapes
// ownership rather than leaking).
func hasStaticStorageSpecifier(decl parser.Node) bool {
	for _, child := range decl.NamedChildren() {
		if child.Kind() == "storage_class_specifier" {
			if child.Text() == "extern" || child.Text() == "static" {
				return true
			}
		}
	}
	return false
}

// hasScalarBaseType reports whether a declaration's base type is a certainly-scalar
// builtin (`primitive_type`/`sized_type_specifier`), or a `type_identifier` that
// resolves to one (`typedef int Status`). A typedef that hides a pointer
// (`typedef char **MsgPdu; MsgPdu p`) or a struct/union/enum base is fail-open.
func hasScalarBaseType(decl parser.Node, typedefs *typedefs) bool {
	for _, child := range decl.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "sized_type_specifier":
			return true
		case "type_identifier":
			if typedefs != nil && typedefs.resolvesToScalar(child.Text()) {
				return true
			}
		}
	}
	return false
}

// declaratorHasPointer reports whether a declarator (sub)tree declares a
// pointer-typed object: `T *p` and `void **p` are true, `T p`, `T a[4]` and a
// function declarator are false. An array of pointers (`int *a[4]`) reports true,
// which is harmless for the caller — an array can never be a whole-variable
// allocation target, and over-reporting a pointer keeps the leak candidate rather
// than silently dropping a real one.
func declaratorHasPointer(node parser.Node) bool {
	if node.Kind() == "pointer_declarator" {
		return true
	}
	for _, c := range node.NamedChildren() {
		if declaratorHasPointer(c) {
			return true
		}
	}
	return false
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
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
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
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
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
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
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

// rootObjectName returns the leftmost base identifier of a field/subscript/
// pointer/cast/parenthesized expression chain (`g_list->next[i]` → "g_list",
// `*out` → "out", `(T*)g_ptr` → "g_ptr"). It returns "" when the chain is not
// rooted in a bare identifier (a call, a literal, or a nested deref `**pp`).
func rootObjectName(node parser.Node) string {
	for {
		switch node.Kind() {
		case "identifier":
			return node.Text()
		case "field_expression", "subscript_expression", "pointer_expression",
			"cast_expression", "parenthesized_expression":
			children := node.NamedChildren()
			if len(children) == 0 {
				return ""
			}
			node = children[0]
		default:
			return ""
		}
	}
}

// storesParamToGlobal reports whether function f stores pointer parameter param
// (by value) into a NON-LOCAL object on some path: a global/static identifier
// (`g_head = p`), a field/subscript of a non-local base (`g_list->next = p`,
// `g_arr[i] = p`), or through a non-local pointer (`*out = p`). This is the
// precise "callee takes ownership of the argument" signal allocatorReturnFuncs
// uses to recognize a get-or-create-and-cache BORROW: a wrapper that registers
// the returned pointer into a global list via a HELPER call (the
// `nlog_set_mon_disk_head(p)` pattern) must not be marked an allocator. A store
// into a LOCAL's field (`local.f = p`) does NOT count — that storage still dies
// with f, so the caller would still own (and leak) the pointer.
func storesParamToGlobal(assigns []parser.Node, f *db.Function, param string, localVars map[string]bool) bool {
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		lhs, rhs, ok := assign.AssignParts()
		if !ok {
			continue
		}
		if argIdentifier(rhs) != param {
			continue
		}
		switch lhs.Kind() {
		case "identifier":
			if !localVars[lhs.Text()] {
				return true
			}
		case "field_expression", "subscript_expression", "pointer_expression":
			if base := rootObjectName(lhs); base != "" && !localVars[base] {
				return true
			}
		}
	}
	return false
}

// globalStoreFuncs returns, keyed by function name, the set of pointer-parameter
// indices that the function stores into a non-local object (a global/static/
// field/subscript/out-param). It is the precise cross-function complement to the
// apikb.IsEscapeFunction naming heuristic: a name like nlog_set_mon_disk_head
// matches neither the `_put`/`_store` tokens nor the configured list, but its
// body `g_mon_disk_head = entry` proves it takes ownership of its argument.
func globalStoreFuncs(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) (map[string]map[int]bool, error) {
	out := make(map[string]map[int]bool)
	err := forEachFile(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		funcDefs := root.FindAll("function_definition")
		assigns := root.FindAll("assignment_expression")
		decls := root.FindAll("declaration")
		for _, f := range funcs {
			params := extractFunctionParamsFrom(funcDefs, f.StartLine)
			localVars := findLocalVarsFrom(decls, f)
			for idx, param := range params {
				if param == "" {
					continue
				}
				if storesParamToGlobal(assigns, f, param, localVars) {
					if out[f.Name] == nil {
						out[f.Name] = make(map[int]bool)
					}
					out[f.Name][idx] = true
				}
			}
		}
	})
	return out, err
}

// passesToGlobalStoreFunc reports whether varName is passed (as a bare
// identifier) to a call whose callee stores that argument position into a
// non-local object — i.e. the callee takes ownership of varName.
func passesToGlobalStoreFunc(calls []parser.Node, f *db.Function, varName string, escapeFuncs map[string]map[int]bool) bool {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		idxs := escapeFuncs[extractCallName(call)]
		if len(idxs) == 0 {
			continue
		}
		args := getCallArgs(call)
		for idx := range idxs {
			if idx < len(args) && argIdentifier(args[idx]) == varName {
				return true
			}
		}
	}
	return false
}

// allocatorReturnFuncs returns the set of function NAMES whose body returns an
// allocator result — either directly (`return malloc(n)`) or via a local
// (`p = malloc(n); ... return p`). This is the "封装成函数" production wrapper
// pattern (docs/req_内存分配释放典型性优化.md): each repo wraps the third-party
// allocator in its own function that NULL-checks and memset_s-initializes before
// returning the pointer. A call to such a wrapper is itself an allocation site
// even when the wrapper's name does not contain "alloc"/"malloc" (the name
// heuristic already covers the nlog_malloc/NAT_MALLOC spellings; this covers the
// custom-named ones). Unlike UncheckedReturnDetector.passthroughAllocFuncs, it
// does NOT require the pointer to be unused between the allocation and the
// return — the NULL-check + memset_s in the wrapper body uses the pointer, which
// is exactly the shape that must still count as an allocator for leak detection.
// allocatorReturnFuncs returns two name sets over the whole scan tree:
//
//   - allocReturns: functions whose body returns an allocator result (a fresh
//     allocation) that the CALLER must free — a call to one is an allocation
//     site.
//   - borrowFuncs: functions that allocate, register the pointer into a global
//     (directly or via a helper that stores its argument to a global), and
//     return the CACHED pointer — a call to one is a BORROW, not an allocation
//     (the caller must NOT free it). This second set is what suppresses the
//     name-heuristic false positive for `nlog_db_create_new_ctrl_item` (its
//     `_new` substring matches apikb.IsAllocator even though it caches).
func allocatorReturnFuncs(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) (allocReturns map[string]bool, borrowFuncs map[string]bool, err error) {
	// Precise cross-function "callee takes ownership of an argument" summary.
	// Computed before the borrow check so every wrapper can see helper functions
	// defined in ANY file, not just the current translation unit.
	escapeFuncs, err := globalStoreFuncs(ctx, store, p, logger)
	if err != nil {
		return nil, nil, err
	}

	returnedSource := make(map[string]map[string]bool)
	borrowFuncs = make(map[string]bool)
	add := func(name, callee string) {
		if callee == "" {
			return
		}
		if returnedSource[name] == nil {
			returnedSource[name] = make(map[string]bool)
		}
		returnedSource[name][callee] = true
	}

	err = forEachFile(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		decls := root.FindAll("declaration")
		for _, f := range funcs {
			localVars := findLocalVarsFrom(decls, f)
			calleeOfVar := make(map[string]string)
			for _, a := range assigns {
				if funcLineRange(f, a.StartLine()) {
					if v, callee := assignCallee(a); v != "" && callee != "" {
						calleeOfVar[v] = callee
					}
				}
			}
			for _, in := range inits {
				if funcLineRange(f, in.StartLine()) {
					if v, callee := assignCallee(in); v != "" && callee != "" {
						calleeOfVar[v] = callee
					}
				}
			}
			for _, ret := range returns {
				if !funcLineRange(f, ret.StartLine()) {
					continue
				}
				if callee := returnedCalleeName(ret); callee != "" {
					add(f.Name, callee)
					continue
				}
				if v := returnedVar(ret); v != "" {
					if callee, ok := calleeOfVar[v]; ok {
						// A wrapper that ESCAPES the returned pointer before
						// returning it (stores it to a global/static/field, or
						// hands it to a container) is a get-or-create-and-cache
						// BORROW: the escape target owns the block, so the
						// wrapper's callers must NOT free it. Marking it an
						// allocator would turn every `x = get_item(...)` into a
						// confirmed false-positive leak (the nlog stat-registry
						// accessor pattern).
						// Strong-evidence borrow only: field/subscript store to a
						// non-local, assign to a non-local identifier, a return, or
						// a hand-off to a helper that itself stores the argument to
						// a global (the nlog_set_mon_disk_head pattern). The
						// escape-function naming heuristic is disabled here — a real
						// allocator wrapper that calls a `_add`/`_store` helper for
						// logging must NOT be misread as a borrow (EL-03); only a
						// helper PROVEN to store its argument to a global counts.
						if len(findEscapeLines(assigns, calls, returns, f, v, localVars, nil, nil, false)) > 0 ||
							passesToGlobalStoreFunc(calls, f, v, escapeFuncs) {
							borrowFuncs[f.Name] = true
							continue
						}
						add(f.Name, callee)
					}
				}
			}
		}
	})
	if err != nil {
		return nil, nil, err
	}

	out := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for name, callees := range returnedSource {
			if out[name] {
				continue
			}
			for callee := range callees {
				if apikb.IsAllocator(callee) || out[callee] {
					out[name] = true
					changed = true
					break
				}
			}
		}
	}
	return out, borrowFuncs, nil
}

// isBorrowCall reports whether expr is (or casts) a call to a function that
// allocatorReturnFuncs identified as a get-or-create-and-cache BORROW. Such a
// call yields a reference the global/list owns, so its caller's assignment is
// not an allocation site — reporting it would be a confirmed false-positive leak.
func isBorrowCall(expr parser.Node, borrowFuncs map[string]bool) bool {
	if len(borrowFuncs) == 0 {
		return false
	}
	if expr.Kind() == "cast_expression" {
		for _, c := range expr.NamedChildren() {
			if isBorrowCall(c, borrowFuncs) {
				return true
			}
		}
		return false
	}
	if expr.Kind() != "call_expression" {
		return false
	}
	return borrowFuncs[extractCallName(expr)]
}

// isMallocExpr reports whether expr is (or casts) a malloc/calloc/realloc call.
// Nested casts (`(int)(size_t)malloc(64)`) are unwrapped recursively. The
// implicit result-returning allocators (strdup/getcwd/...) are recognized via
// apikb.IsAllocator, and realpath(path, NULL) — which allocates only when its
// second argument is NULL — is recognized explicitly (ML-11). A callee in
// allocReturns (a wrapper function that returns an allocator result) is also an
// allocation site (the "封装成函数" pattern).
func isMallocExpr(expr parser.Node, allocReturns map[string]bool) bool {
	if expr.Kind() == "cast_expression" {
		for _, c := range expr.NamedChildren() {
			if isMallocExpr(c, allocReturns) {
				return true
			}
		}
		return false
	}
	if expr.Kind() != "call_expression" {
		return false
	}
	name := extractCallName(expr)
	if apikb.IsAllocator(name) || allocReturns[name] {
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
