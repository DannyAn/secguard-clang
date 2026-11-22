package evidence

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// leakAllocSite is one allocation site: the source line and the full tracking key
// (the bare variable name, or the base+field path for a field/subscript store).
type leakAllocSite struct {
	line int
	key  string
}

func (d *MemoryLeakDetector) findAllocations(ctx context.Context, f *db.Function, file *db.File, assigns, inits, calls []parser.Node, allocReturns, borrowFuncs map[string]bool, scalarVars map[string]bool, bumpAllocators map[string]bool) map[string][]leakAllocSite {
	allocs := make(map[string][]leakAllocSite)

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
		// A bump/arena allocator's result is an interior pointer into a pool the
		// arena owner releases wholesale, so it never leaks per-object.
		if callee := callCalleeName(rhs); callee != "" && bumpAllocators[callee] {
			return
		}
		key := allocTrackKey(lhs)
		if key == "" {
			return
		}
		// A whole-variable store to a SCALAR local (bool/int/uint32_t/...) is a
		// status-code assignment, not a heap allocation, even when the callee
		// name triggers the zero-config allocator heuristic (`_new`, `remalloc`,
		// `*_alloc`). Only a pointer-typed target can hold an allocation; a
		// known-scalar local is skipped. Typedef'd pointer types (`MsgPdu p` =
		// `char **p`) are NOT in scalarVars, so they stay candidates (fail-open)
		// — never a silent false negative.
		if lhs.Kind() == "identifier" && scalarVars[key] {
			return
		}
		base := allocKeyBase(key)
		allocs[base] = append(allocs[base], leakAllocSite{line: node.StartLine(), key: key})
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
			allocs[name] = append(allocs[name], leakAllocSite{line: call.StartLine(), key: name})
		}
	}

	for name := range allocs {
		sort.Slice(allocs[name], func(i, j int) bool { return allocs[name][i].line < allocs[name][j].line })
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

func (d *MemoryLeakDetector) findFrees(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, macros map[string]macroFreeSummary, inits, assigns []parser.Node, summaries summaryMap) map[string][]freeCall {
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
				recordFree(freeArgKey(args[0]), call.StartLine(), "free")
			}
			continue
		}
		if apikb.IsDeclaredDeallocator(callName) {
			// A DECLARED deallocator (free/freeaddrinfo/freeifaddrs + registered)
			// frees its FIRST argument by contract, so `free(p)` releases p.
			if args := getCallArgs(call); len(args) > 0 {
				recordFree(freeArgKey(args[0]), call.StartLine(), callName)
			}
			continue
		}
		// Arbitrarily-named release helper (issue #281 M1 residual) OR a
		// heuristic deallocator (name ends "free"/"free_f" or contains
		// "_destroy"/"_delete"/"_cleanup"/"_recycle" but is not declared): a
		// callee whose body frees a pointer parameter directly (`void
		// table_teardown(T *t){ ...; free(t); }`) releases that argument even
		// though the name alone does not prove WHICH parameter is freed.
		// ParamDirectFrees is the every-path direct-free fact keyed by parameter
		// index, so a helper may release any argument position, not only the
		// first (`void release(int n, T *t){ free(t); }` frees the second, and
		// `void pair_destroy(int flags, T *t){ free(t); }` frees the second even
		// though "_destroy" matches the deallocator heuristic). A field-only free
		// (ParamFieldFrees) does NOT release the base pointer and stays a leak,
		// matching the supplement's "helper releases only members" case.
		if s, ok := summaries[callName]; ok {
			args := getCallArgs(call)
			for argIdx, arg := range args {
				if s.ParamDirectFrees[argIdx] {
					recordFree(freeArgKey(arg), call.StartLine(), callName)
				}
			}
			continue
		}
		// A heuristic deallocator with no in-tree summary (an external
		// `nlog_free(p)` / `nat_free(p)` wrapper) has only the name convention:
		// the deallocator-shaped name releases its first argument.
		if apikb.IsDeallocator(callName) {
			if args := getCallArgs(call); len(args) > 0 {
				recordFree(freeArgKey(args[0]), call.StartLine(), callName)
			}
		}
	}
	return frees
}

// argIdentifier returns the bare identifier of a release-call argument, unwrapping
// cast and parenthesized expressions (`free((void *)p)` → "p", ML-06). A non-trivial
// expression (`free(p + i)`) is NOT unwrapped and returns "", because it does not
// release a single tracked variable.
//
// The `&` address-of operator is unwrapped (`cleanup(&s)` → "s") so a project
// deallocator / ownership-transfer call that takes a struct by address and
// releases its fields (the IPsec `IKE_ModeCfgExtFreeProductMemory(&st)` idiom)
// matches a field-store allocation `st.field = malloc(...)`, whose tracked
// varName is the struct base. Without this, the field store is not recognized
// as released and every "alloc → store into local struct field → cleanup(&struct)"
// site is a false-positive memory-leak (Issue #241 memory-leak mode C).
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
		text := strings.TrimSpace(arg.Text())
		if strings.HasPrefix(text, "*") || strings.HasPrefix(text, "&") {
			for _, c := range arg.NamedChildren() {
				if id := argIdentifier(c); id != "" {
					return id
				}
			}
		}
	}
	return ""
}

// allocTrackKey returns the full tracking key of an allocation or release
// target: the bare identifier for `p`, the base+field path for a field access
// (`p.field`, `p->field`) and the base+index for a subscript (`arr[0]`, `arr[]`
// for a variable index). Two fields of one struct are distinct keys, so
// `p.a = malloc(); p.b = malloc(); free(p.a);` releases only `p.a` while `p.b`
// still leaks (Issue #288). It returns "" for a target it cannot name (a call,
// a nested field chain whose base is not a bare identifier, ...).
func allocTrackKey(node parser.Node) string {
	switch node.Kind() {
	case "identifier":
		return node.Text()
	case "field_expression":
		base, field := extractFieldAccess(node)
		if base == "" || field == "" {
			return ""
		}
		return base + "." + field
	case "subscript_expression":
		base, field := subscriptAccess(node)
		if base == "" || field == "" {
			return ""
		}
		return field
	case "pointer_expression":
		// `*root = malloc()` stores into the pointee of root (an output
		// parameter): track it under the base identifier, matching the release
		// `cJSON_Delete(*root)` which argIdentifier unwraps to "root".
		for _, c := range node.NamedChildren() {
			if c.Kind() == "identifier" {
				return c.Text()
			}
		}
	case "pointer_declarator", "array_declarator", "function_declarator",
		"parenthesized_declarator", "init_declarator":
		// `char *p = malloc(...)` / `int *arr = malloc(...)`: the LHS of an
		// init_declarator is its declarator, whose bound identifier is the
		// whole-variable allocation target.
		return declaredIdentifier(node)
	}
	return ""
}

// allocKeyBase returns the base identifier of a tracking key: "s" for "s.field"
// and "s[0]", and the key itself for a bare identifier. A whole-struct release
// (`cleanup(&s)`) is recorded under the base and releases every field allocation
// under that base.
func allocKeyBase(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == '.' || key[i] == '[' {
			return key[:i]
		}
	}
	return key
}

// freeArgKey returns the tracking key of a release-call argument. It mirrors
// argIdentifier's cast/parenthesized/address-of unwrapping, but maps a field or
// subscript argument (`free(p->f)` / `free(p.field)` / `free(a[0])`) to its
// full path key instead of dropping it, so it pairs with the matching
// field-store allocation. A bare identifier or an address-of (`cleanup(&s)`)
// still maps to the base, which releases the whole variable/struct.
func freeArgKey(arg parser.Node) string {
	switch arg.Kind() {
	case "identifier":
		return arg.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range arg.NamedChildren() {
			if id := freeArgKey(c); id != "" {
				return id
			}
		}
	case "pointer_expression":
		text := strings.TrimSpace(arg.Text())
		if strings.HasPrefix(text, "*") || strings.HasPrefix(text, "&") {
			for _, c := range arg.NamedChildren() {
				if id := freeArgKey(c); id != "" {
					return id
				}
			}
		}
	case "field_expression", "subscript_expression":
		return allocTrackKey(arg)
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
		// Field-prefix match: when the tracked varName is a struct base ("s")
		// because the allocation is stored into a field (`s.field = malloc(...)`),
		// a null check on the field (`!s.field`, `s.field == NULL`) protects the
		// allocation on that branch. Without this, `if (!s.field) return;` is not
		// recognized as a null-guard return, so hasLostResource finds a path from
		// the allocation through the early return to exit, avoiding the later
		// cleanup call — every "alloc → store into local struct field →
		// if(!field) return → cleanup(&struct)" site is a false-positive leak
		// (Issue #241 memory-leak mode C).
		if strings.HasPrefix(v, varName+".") || strings.HasPrefix(v, varName+"->") {
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
		text := strings.TrimSpace(node.Text())
		neg := strings.HasPrefix(text, "-")
		if op == "<" {
			// `< 0` (and any negative bound): failure for a non-negative-or
			// -1 status domain. A POSITIVE bound (`< 5`) is a length/count
			// comparison — asprintf/getline return non-negative counts on
			// success, so such a guard fires on a SUCCESS branch where the
			// allocation exists and the early return is a real leak. Reject
			// it rather than suppress the leak.
			if v, err := strconv.ParseInt(text, 0, 64); err == nil {
				return v <= 0
			}
			return neg
		}
		return neg
	case "unary_expression":
		// `-1` spelled as unary minus.
		return op == "==" || op == "!=" || op == "<"
	}
	return false
}
