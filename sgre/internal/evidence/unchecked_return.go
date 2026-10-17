package evidence

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// UncheckedReturnDetector flags calls to allocation / I/O functions whose
// return value is neither compared directly nor stored into a variable that is
// subsequently checked (CWE-252). This is the C analogue of "missing error
// handling": malloc can return NULL, read/recv can return -1, and ignoring that
// turns a soft failure into a crash or a corruption.
type UncheckedReturnDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUncheckedReturnDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UncheckedReturnDetector {
	return &UncheckedReturnDetector{store: store, parser: p, logger: logger}
}

func (d *UncheckedReturnDetector) Name() string { return "unchecked_return" }

func (d *UncheckedReturnDetector) Domain() string { return "boundary" }

func (d *UncheckedReturnDetector) Capabilities() []string {
	return []string{"null-return", "error-return"}
}

// uncheckedReturnAPIs are calls whose return value must be validated. The
// failure sentinel (NULL or a negative errno value) is irrelevant to the
// detection — only that the value must be checked before use.
var uncheckedReturnAPIs = map[string]bool{
	"malloc": true, "calloc": true, "realloc": true,
	"fopen": true, "fdopen": true, "opendir": true,
	"read": true, "recv": true, "write": true, "send": true,
}

func (d *UncheckedReturnDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Empty-run skip (P0-5): the detector only flags calls to an unchecked-return
	// API or an allocator. Pre-scan for that trigger; when absent, the expensive
	// passthrough-allocator fixpoint + return-type table + per-file pass are
	// provably empty and skipped.
	if !d.hasUncheckedReturnCandidate(ctx) {
		return result, nil
	}

	// User wrappers that return an unchecked allocation result (e.g.
	// `void *x_malloc(n) { return malloc(n); }`) are passthrough allocators:
	// a call to one must be NULL-checked at the call site exactly like the
	// wrapped allocator. Compute that set once so the per-file pass below
	// treats calls to them as unchecked-return sources too. The same pass
	// collects each function's entry NULL-reject parameters, which the per-file
	// pass uses to recognise a value the callee has already validated.
	summaries, err := d.funcSummaries(ctx)
	if err != nil {
		return result, err
	}
	passthrough := summaries.passthrough

	retTypes, err := d.funcReturnTypes(ctx)
	if err != nil {
		return result, err
	}

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		ids := root.FindAll("identifier")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		dos := root.FindAll("do_statement")
		conds := root.FindAll("conditional_expression")
		switches := root.FindAll("switch_statement")
		inits := root.FindAll("init_declarator")
		decls := root.FindAll("declaration")

		// Function parameter names, keyed by the definition's start line. An
		// assignment target that is neither a function-local declaration nor a
		// parameter is a file-scope/global/external storage whose "checked"
		// state lives at its use sites in OTHER functions — invisible to the
		// function-scoped checked analysis below.
		paramsByLine := make(map[int]map[string]bool)
		for _, fnNode := range root.FindAll("function_definition") {
			set := make(map[string]bool)
			for _, p := range paramPositions(fnNode) {
				if p != "" {
					set[p] = true
				}
			}
			paramsByLine[fnNode.StartLine()] = set
		}

		for _, f := range funcs {
			checked := d.checkedVars(ifs, whiles, fors, dos, conds, switches, calls, returns, f)
			// A local object whose name matches a built-in unchecked-return API
			// shadows it: `int (*read)(void *, size_t, void *);` declares a
			// function pointer, so `read(buf, n, ctx)` is not POSIX read(). The
			// declaration must precede the call for it to be in scope at it.
			localDeclLines := make(map[string]int)
			noteDecl := func(node parser.Node) {
				name := extractVarFromDeclarator(node)
				if name == "" {
					return
				}
				if line, ok := localDeclLines[name]; !ok || node.StartLine() < line {
					localDeclLines[name] = node.StartLine()
				}
			}
			for _, decl := range decls {
				if !funcLineRange(f, decl.StartLine()) {
					continue
				}
				if declarator := decl.ChildByFieldName("declarator"); declarator != nil {
					noteDecl(*declarator)
				}
			}
			for _, init := range inits {
				if !funcLineRange(f, init.StartLine()) {
					continue
				}
				noteDecl(init)
			}
			indirectGuarded := indirectGuardedVars(calls, f, checked, summaries.nullRejectParams)
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				callee := extractCallName(call)
				if !uncheckedReturnAPIs[callee] && !passthrough[callee] && !apikb.IsAllocator(callee) {
					continue
				}
				if apikb.IsNonNullReturning(callee) {
					continue
				}
				if line, ok := localDeclLines[callee]; ok && uncheckedReturnAPIs[callee] && line < call.StartLine() {
					continue
				}
				// A function that is neither a built-in unchecked-return API
				// nor a declared allocator must return a pointer to be an
				// unchecked-return source. This applies to passthrough wrappers
				// too: the passthrough fixpoint admits a wrapper via the broad
				// "alloc" substring heuristic (`void w(){ return is_allocated(p); }`),
				// and without a pointer return type a bare `w()` call has no
				// NULL-returning result to check. A void or scalar function whose
				// name happens to contain "alloc" (test_case_alloc,
				// check_alloc_status, is_allocated,
				// storage_spec_generator_log_allocate_size_init) is a false
				// positive, so flagging its call site is skipped. An external
				// function not in the index is likewise fail-closed: the "alloc"
				// substring heuristic is too broad to trust without a confirmed
				// pointer return type.
				// A callee that is neither a built-in unchecked-return API nor a
				// declared allocator is only a source because its NAME matches the
				// allocator heuristic (alloc/strdup/_new/_dup/...) and it returns a
				// pointer. That is a name guess, not a known failure contract:
				// contractKnown is false so the planner hands it to the AI (Hint
				// contract@unknown) instead of auto-confirming. The AI must prove
				// the callee returns a failure sentinel or dismiss.
				contractKnown := uncheckedReturnAPIs[callee] || apikb.IsDeclaredAllocator(callee) || passthrough[callee]
				if !uncheckedReturnAPIs[callee] && !apikb.IsDeclaredAllocator(callee) {
					rt, ok := retTypes[callee]
					if !ok || !strings.HasSuffix(rt, "*") {
						continue
					}
				}
				if callResultChecked(call) {
					continue
				}
				// A (void) cast is the programmer's explicit "intentionally
				// ignoring this return value" annotation. For an allocator-name
				// heuristic match (not a declared allocator, not an unchecked-
				// return API, not a passthrough wrapper), the function may use an
				// out-parameter or error-code pattern where the return value is
				// not the allocation result — respect the (void) intent. Declared
				// allocators (malloc/calloc/realloc) and unchecked-return APIs
				// (fopen/read/...) still must be checked even when cast to void:
				// (void)malloc(n) is a genuine CWE-252 defect.
				if isVoidCast(call) && !uncheckedReturnAPIs[callee] && !passthrough[callee] && !apikb.IsDeclaredAllocator(callee) {
					continue
				}
				// A wrapper that hands the value straight back to its caller
				// (`void *x_malloc(size_t n) { return malloc(n); }`) is a passthrough:
				// the caller -- which sees x_malloc's return -- is responsible for the
				// NULL check, not the wrapper. Flagging the wrapper is a false
				// positive, so skip it.
				if callResultReturned(call) {
					continue
				}
				// A name-heuristic match (contract@unknown) whose result is stored to
				// a non-local (global/static/external) variable is not an
				// unchecked-return defect: the "check" for a global is cross-function
				// and invisible to this function-scoped detector, and the contract is
				// only a name guess. A genuine NULL global is caught by null-deref at
				// its use site, not by unchecked-return at the store.
				if !contractKnown && anyGlobalTarget(assignedVarsOfCall(call), localDeclLines, paramsByLine[f.StartLine]) {
					continue
				}
				if vars := assignedVarsOfCall(call); len(vars) > 0 {
					checkedAny := false
					for _, v := range vars {
						if checked[v] || indirectGuarded[v] {
							checkedAny = true
							break
						}
					}
					if checkedAny {
						continue
					}
					// `void *p = malloc(n); return p;` is a passthrough allocator:
					// the caller checks, so the wrapper's malloc must not be flagged.
					if passthroughReturnVar(vars[0], call.StartLine(), f, returns, ids, checked) {
						continue
					}
					// A pointer whose ONLY later use is `free(p)` has no
					// unchecked-return defect: free(NULL) is a defined no-op, so
					// an unnoticed failure cannot corrupt or crash anything. The
					// classic false positive is `p = malloc(n); free(p);` (e.g.
					// tp_sizeof_pointer), which used to reach the auto-confirmed
					// tier as a confirmed CWE-252 finding.
					if onlyFreedAfter(vars, call, f, ids) {
						continue
					}
				}

				if emitEvent(ctx, d.store, d.logger, "UNCHECKED_RETURN", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
					"function":       extractCallName(call),
					"expression":     call.OriginalText(),
					"category":       "unchecked_return",
					"contract_known": strconv.FormatBool(contractKnown),
				}) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// checkedVars returns the set of variable names that are validated somewhere in
// f: compared against a sentinel (`p == NULL`, `ret < 0`), negated (`!p`), used
// as a bare truthiness condition (`if (p)`), or consumed as the comparison a
// return statement hands to the caller (`return f != 0;`). A condition that
// merely dereferences the variable (`if (p->len > 0)`) is NOT a null/error
// check, so it must not mark `p` checked — that would suppress a genuine
// CWE-252 defect (the allocation's failure is never handled before `p` is
// used). This mirrors the planner's ReturnCheckFilter (conditionTestsVar) so
// the detector and the convergence filter agree on what "checked" means.
func (d *UncheckedReturnDetector) checkedVars(ifs, whiles, fors, dos, conds, switches, calls, returns []parser.Node, f *db.Function) map[string]bool {
	set := make(map[string]bool)
	for _, cond := range [][]parser.Node{ifs, whiles, fors, dos, conds} {
		for _, node := range cond {
			if !funcLineRange(f, node.StartLine()) {
				continue
			}
			c := node.ChildByFieldName("condition")
			if c == nil {
				continue
			}
			for _, id := range testedOperands(*c) {
				set[id] = true
			}
			for _, v := range bareConditionVars(c) {
				set[v] = true
			}
		}
	}
	for _, sw := range switches {
		if !funcLineRange(f, sw.StartLine()) {
			continue
		}
		c := sw.ChildByFieldName("condition")
		if c == nil {
			continue
		}
		for _, id := range testedOperands(*c) {
			set[id] = true
		}
		if v := bareOperandVar(*c); v != "" {
			set[v] = true
		}
	}
	// `return f != 0;` hands the stored call result to the caller as a boolean
	// predicate: the failure sentinel decides the function's own return value,
	// so the result IS consumed. Without this, `FILE *f = fopen(p, "r");
	// return f != 0;` was emitted as an unchecked return and reached the
	// auto-confirmed tier (benchmark p10 round-3). Only a comparison counts —
	// a bare `return f;` stays the passthrough wrapper's own contract.
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		for _, child := range ret.NamedChildren() {
			for _, v := range testedOperands(child) {
				set[v] = true
			}
		}
	}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) || extractCallName(call) != "assert" {
			continue
		}
		if p := call.Parent(); p == nil || p.Kind() != "expression_statement" {
			continue
		}
		args := getCallArgs(call)
		if len(args) == 0 {
			continue
		}
		for _, varName := range assertGuardedVars(args[0]) {
			set[varName] = true
		}
	}
	return set
}

// testedOperands returns the variable/member/element expressions that a
// condition's comparison operator directly tests for null/error. `if (p->len > 0)`
// compares p->len, not p, so it yields nothing — the field's value is a length,
// not a sentinel. `if (e->buffer == NULL)` yields e->buffer.
func testedOperands(cond parser.Node) []string {
	var out []string
	for _, b := range cond.FindAll("binary_expression") {
		if !hasCompareOp(b) {
			continue
		}
		for _, child := range b.NamedChildren() {
			if v := testedOperandVar(child); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// testedOperandVar returns the storage location a comparison operand tests, or
// "" when the operand is not a direct null/error test target. `if (p == NULL)`
// yields "p"; `if (p->len == 0)` yields "p->len" (the field, not p); and the
// assignment-in-condition idiom `if ((p = fopen(...)) == NULL)` yields "p" — the
// comparison tests the freshly assigned value, so the assigned location is the
// test target.
func testedOperandVar(operand parser.Node) string {
	switch operand.Kind() {
	case "identifier", "field_expression", "subscript_expression", "pointer_expression":
		return operand.Text()
	case "parenthesized_expression":
		for _, child := range operand.NamedChildren() {
			if v := testedOperandVar(child); v != "" {
				return v
			}
		}
	case "assignment_expression":
		children := operand.NamedChildren()
		if len(children) > 0 {
			return assignedVariable(children[0])
		}
	}
	return ""
}

// bareConditionVars returns the variable names a condition tests directly via
// bare truthiness (`if (p)`) or negation (`if (!p)` / `if (!e->buffer)`), and
// recurses into `||`/`&&` combinations so the delayed merge-check idiom
// `if (!a || !b || !c)` registers a, b, and c. Parentheses are unwrapped.
func bareConditionVars(cond *parser.Node) []string {
	if cond == nil {
		return nil
	}
	n := *cond
	for n.Kind() == "parenthesized_expression" {
		inner := n.NamedChildren()
		if len(inner) == 0 {
			return nil
		}
		n = inner[0]
	}
	if n.Kind() == "identifier" {
		return []string{n.Text()}
	}
	// `if (!p)` / `if (!e->buffer)` — the negation of the variable itself is a
	// null/error check; negating a derived value (`if (!(p->len > 0))`) is not.
	if n.Kind() == "unary_expression" && strings.HasPrefix(strings.TrimSpace(n.Text()), "!") {
		for _, child := range n.NamedChildren() {
			switch child.Kind() {
			case "identifier", "field_expression", "subscript_expression":
				return []string{child.Text()}
			}
		}
	}
	// Recurse into || / && so `if (!a || !b || !c)` registers a, b, c.
	if n.Kind() == "binary_expression" {
		op := parser.BinaryOperator(n)
		if op == "||" || op == "&&" {
			var vars []string
			for _, child := range n.NamedChildren() {
				vars = append(vars, bareConditionVars(&child)...)
			}
			return vars
		}
		if op == "&" {
			var vars []string
			for _, child := range n.NamedChildren() {
				switch child.Kind() {
				case "identifier", "field_expression", "subscript_expression":
					vars = append(vars, child.Text())
				}
			}
			return vars
		}
	}
	return nil
}

// indirectGuardedVars returns the variables whose unchecked-return event another
// call in the same function has already handled. The shape is
//
//	filter = idm_db_filter_new(2);
//	ret = idm_fill_filter(filter, ...);   /* entry-guards its NULL parameter */
//	if (ret != 0) { ... return ret; }     /* caller acts on the failure */
//
// `filter` is passed as argument i of a callee whose parameter i is rejected at
// entry with a failure return (nullRejectParams), and the call's result is
// acted on — either tested inline (`if (wrap(p) != 0)`) or stored in a variable
// that is itself checked. A NULL `filter` therefore becomes an error the caller
// handles, so the unchecked-return candidate on the source call is a false
// positive. Requiring the callee's entry guard is what keeps a
// dereferencing call such as `if (strlen(p) > 0)` reportable: the argument is
// used, not validated.
func indirectGuardedVars(calls []parser.Node, f *db.Function, checked map[string]bool, nullRejectParams map[string]map[int]bool) map[string]bool {
	if len(nullRejectParams) == 0 {
		return nil
	}
	// The variables a call's result is stored into, with the assignment line:
	// only a variable that is itself a call result can carry an
	// unchecked-return event.
	callResultVars := make(map[string]int)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		for _, v := range assignedVarsOfCall(call) {
			if v == "" {
				continue
			}
			if _, ok := callResultVars[v]; !ok {
				callResultVars[v] = call.StartLine()
			}
		}
	}
	var out map[string]bool
	for _, call := range calls {
		line := call.StartLine()
		if !funcLineRange(f, line) {
			continue
		}
		rejects := nullRejectParams[extractCallName(call)]
		if len(rejects) == 0 {
			continue
		}
		if !callResultChecked(call) {
			checkedResult := false
			for _, v := range assignedVarsOfCall(call) {
				if checked[v] {
					checkedResult = true
					break
				}
			}
			if !checkedResult {
				continue
			}
		}
		args := getCallArgs(call)
		for i, arg := range args {
			if !rejects[i] || arg.Kind() != "identifier" {
				continue
			}
			name := arg.Text()
			assignLine, ok := callResultVars[name]
			if !ok || assignLine >= line {
				continue
			}
			if out == nil {
				out = make(map[string]bool)
			}
			out[name] = true
		}
	}
	return out
}

// entryNullRejectParams returns the 0-based parameter indices a function rejects
// at entry: a top-level `if` whose NULL-direction branch returns a failure
// sentinel (`if (p == NULL) return -1;` rejects parameter p). The polarity
// matters — `if (p != NULL) { ... } else { return -1; }` rejects p too (the
// branch taken when p is NULL returns), while `if (p != NULL) return 0;` does
// not. A branch that returns success (bare `return;`, `return 0;`) is not a
// rejection: the caller's `ret != 0` test could not detect a NULL argument.
func entryNullRejectParams(fnNode parser.Node) map[int]bool {
	body := fnNode.FindFirst("compound_statement")
	if body == nil {
		return nil
	}
	params := paramPositions(fnNode)
	if len(params) == 0 {
		return nil
	}
	index := make(map[string]int, len(params))
	for i, name := range params {
		if name == "" {
			continue
		}
		if _, dup := index[name]; !dup {
			index[name] = i
		}
	}
	var out map[int]bool
	mark := func(vars []string) {
		for _, v := range vars {
			i, ok := index[v]
			if !ok {
				continue
			}
			if out == nil {
				out = make(map[int]bool)
			}
			out[i] = true
		}
	}
	for _, stmt := range body.NamedChildren() {
		if stmt.Kind() != "if_statement" {
			continue
		}
		cond := stmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		// NullCheckedVars = the variables the condition proves NULL when it is
		// false, i.e. the ones the then-branch sees as NULL; GuardedNonnullVars
		// is the dual for the else-branch.
		if cons := stmt.ChildByFieldName("consequence"); cons != nil && branchFailureReturns(*cons) {
			mark(parser.NullCheckedVars(*cond))
		}
		if alt := stmt.ChildByFieldName("alternative"); alt != nil && branchFailureReturns(*alt) {
			mark(parser.GuardedNonnullVars(*cond))
		}
	}
	return out
}

// branchFailureReturns reports whether a branch body returns a failure sentinel:
// any `return <value>` whose value is not provably zero/success. A bare
// `return;` cannot be observed by a `ret != 0` test and `return 0;` reports
// success, so neither counts. Non-numeric error tokens (`return IDM_ERR;`),
// `return -1;` and `return NULL;` all count.
func branchFailureReturns(branch parser.Node) bool {
	for _, ret := range branch.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		text := stripCastsAndParens(children[0].Text())
		if text == "" || text == "0" || text == "false" || text == "FALSE" {
			continue
		}
		return true
	}
	return false
}

// paramPositions returns a function definition's parameter names in declaration
// order, keeping an empty entry for an unnamed parameter so a call argument's
// index still lines up with the declaration (`int f(int, char *p)` → ["", "p"]).
func paramPositions(fnNode parser.Node) []string {
	var decl parser.Node
	for _, child := range fnNode.NamedChildren() {
		switch child.Kind() {
		case "function_declarator":
			decl = child
		case "pointer_declarator":
			for _, gc := range child.NamedChildren() {
				if gc.Kind() == "function_declarator" {
					decl = gc
				}
			}
		}
		if decl.Kind() != "" {
			break
		}
	}
	if decl.Kind() == "" {
		return nil
	}
	var out []string
	for _, child := range decl.NamedChildren() {
		if child.Kind() != "parameter_list" {
			continue
		}
		for _, param := range child.NamedChildren() {
			if param.Kind() != "parameter_declaration" {
				continue
			}
			name := ""
			for _, pc := range param.NamedChildren() {
				if v := extractVarFromDeclarator(pc); v != "" {
					name = v
					break
				}
			}
			out = append(out, name)
		}
	}
	return out
}

// callResultChecked reports whether the call's value is consumed directly by a
// comparison, a `!` negation, or a branch/loop condition — i.e. validated at
// the call site without going through a named variable.
func callResultChecked(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "binary_expression":
			if hasCompareOp(*p) {
				return true
			}
		case "unary_expression":
			if strings.HasPrefix(strings.TrimSpace(p.Text()), "!") {
				return true
			}
		case "if_statement", "while_statement", "for_statement", "do_statement", "switch_statement":
			return true
		case "return_statement", "expression_statement", "compound_statement",
			"declaration", "argument_list", "assignment_expression", "init_declarator":
			return false
		}
	}
	return false
}

// isVoidCast reports whether the call is wrapped in a (void) cast — the
// programmer's explicit "intentionally ignoring this return value" annotation.
// `(void)foo()` → true; `(int)foo()` / `foo()` → false.
func isVoidCast(call parser.Node) bool {
	p := call.Parent()
	if p.Kind() != "cast_expression" {
		return false
	}
	for _, child := range p.NamedChildren() {
		if child.Kind() == "type_descriptor" {
			return typeSpelling(child) == "void"
		}
	}
	return false
}

// callResultReturned reports whether the call's result flows straight into a
// `return` (possibly through casts/parentheses) without being stored in a
// variable or otherwise consumed first. `void *x_malloc(size_t n) { return
// malloc(n); }` is a passthrough allocator: the caller — which sees x_malloc's
// return value — is responsible for the NULL check, so the wrapper itself must
// not be flagged as an unchecked return.
func callResultReturned(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "parenthesized_expression", "cast_expression":
			continue
		case "return_statement":
			return true
		default:
			return false
		}
	}
	return false
}

// assignedVarsOfCall returns the storage locations the call's result is assigned
// into, collecting ALL targets in a (possibly chained) assignment. For
// `v = call(...)` / `T v = call(...)` it returns [v]; for a chained assignment
// `a = b = call(...)` it returns [b, a] (innermost first), so a null-check on
// EITHER target suppresses the unchecked-return event. Returns nil when the
// result is not stored in a named variable.
func assignedVarsOfCall(call parser.Node) []string {
	var vars []string
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression":
			named := p.NamedChildren()
			if len(named) < 2 {
				return vars
			}
			vars = append(vars, assignedLocationText(named[0]))
		case "init_declarator":
			named := p.NamedChildren()
			if len(named) < 2 {
				return vars
			}
			vars = append(vars, assignedLocationText(named[0]))
			return vars
		case "parenthesized_expression", "cast_expression", "binary_expression",
			"argument_list", "call_expression", "field_expression", "subscript_expression":
			continue
		default:
			return vars
		}
	}
	return vars
}

// assignedLocationText returns the storage location an assignment writes: a
// bare variable/field/subscript, or the POINTED-TO location `*p` for
// `*p = malloc(n)`. Unlike assignedVariable (which treats `*p = f()` as an
// output-parameter write and returns "" for the null-source detector's
// semantics), this returns "*p" so the unchecked-return detector can match
// `*p = malloc(n)` against a later `if (*p == NULL)` check.
func assignedLocationText(lhs parser.Node) string {
	if lhs.Kind() == "pointer_expression" {
		return lhs.Text()
	}
	return assignedVariable(lhs)
}

// anyGlobalTarget reports whether any assigned location is NOT a function-local
// storage — i.e. a file-scope global/static, an external, or a field/subscript
// of one (`g_s.f`, `g_arr[i]`). A location is local when its base identifier is
// a function-local declaration (locals) or a parameter (params).
func anyGlobalTarget(vars []string, locals map[string]int, params map[string]bool) bool {
	for _, v := range vars {
		if v == "" {
			continue
		}
		base := v
		if b := locationBase(v); b != "" {
			base = b
		}
		if _, isLocal := locals[base]; isLocal {
			continue
		}
		if params[base] {
			continue
		}
		return true
	}
	return false
}

// locationBase returns the base variable of a field/subscript location
// (`g_s.f`, `g_arr[i]` -> "g_s"/"g_arr"), or "" for a bare identifier.
func locationBase(v string) string {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '-':
			if i+1 < len(v) && v[i+1] == '>' {
				return strings.TrimSpace(v[:i])
			}
		case '.', '[':
			return strings.TrimSpace(v[:i])
		}
	}
	return ""
}

// hasCompareOp reports whether a binary expression is an equality/relational
// comparison (==, !=, <, <=, >, >=) — the operators used to validate a return
// value (NULL / -1 / 0 / bounds).
func hasCompareOp(expr parser.Node) bool {
	for _, child := range expr.Children() {
		switch child.Kind() {
		case "==", "!=", "<", "<=", ">", ">=":
			return true
		}
	}
	return false
}

// funcReturnTypes returns a map from function name to its return type for every
// indexed function. The unchecked-return detector uses this to reject alloc-name
// heuristic matches that cannot be allocators: an allocator must return a
// pointer, so a void or scalar function whose name contains "alloc" (e.g.
// test_case_alloc, check_alloc_status) is a false positive source.
func (d *UncheckedReturnDetector) funcReturnTypes(ctx context.Context) (map[string]string, error) {
	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("unchecked return: list functions: %w", err)
	}
	types := make(map[string]string, len(funcs))
	for _, f := range funcs {
		types[f.Name] = f.ReturnType
	}
	declarations, err := d.store.ListFunctionDeclarations(ctx)
	if err != nil {
		return nil, fmt.Errorf("unchecked return: list function declarations: %w", err)
	}
	for _, dcl := range declarations {
		if _, defined := types[dcl.Name]; !defined {
			types[dcl.Name] = dcl.ReturnType
		}
	}
	return types, nil
}

// funcSummaries bundles the two cross-function facts the detector derives from
// a single pass over the indexed functions.
type funcSummaries struct {
	// passthrough names the functions whose body returns an unchecked
	// allocation result without checking it — directly (`return malloc(n)`) or
	// via an unchecked variable (`void *p = malloc(n); return p;`), or
	// transitively (`return other_wrapper(...)`). A call to such a wrapper must
	// be NULL-checked at the call site exactly like the allocator it wraps, so
	// the main detection pass treats calls to them as unchecked-return sources.
	passthrough map[string]bool
	// nullRejectParams maps a function name to the 0-based indices of the
	// parameters it rejects at entry with a failure return (see
	// entryNullRejectParams).
	nullRejectParams map[string]map[int]bool
}

// hasUncheckedReturnCandidate pre-scans every indexed file for the detector's
// trigger: a call to an unchecked-return API or an allocator-name function. When
// absent, the full detection is provably empty and skipped. A scan error fails
// open (returns true) so the full detector still runs.
func (d *UncheckedReturnDetector) hasUncheckedReturnCandidate(ctx context.Context) bool {
	found := false
	err := forEachFileIncludingEmpty(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		if found {
			return
		}
		for _, call := range root.FindAll("call_expression") {
			name := extractCallName(call)
			if uncheckedReturnAPIs[name] || apikb.IsAllocator(name) {
				found = true
				return
			}
		}
	})
	if err != nil {
		return true
	}
	return found
}

func (d *UncheckedReturnDetector) funcSummaries(ctx context.Context) (*funcSummaries, error) {
	// returnedSource maps a function name to the set of callee names whose result
	// it returns to its caller.
	returnedSource := make(map[string]map[string]bool)
	nullReject := make(map[string]map[int]bool)

	add := func(name, callee string) {
		if callee == "" {
			return
		}
		if returnedSource[name] == nil {
			returnedSource[name] = make(map[string]bool)
		}
		returnedSource[name][callee] = true
	}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		returns := root.FindAll("return_statement")
		ids := root.FindAll("identifier")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		dos := root.FindAll("do_statement")
		conds := root.FindAll("conditional_expression")
		switches := root.FindAll("switch_statement")

		nameByLine := make(map[int]string, len(funcs))
		for _, f := range funcs {
			nameByLine[f.StartLine] = f.Name
		}
		for _, fnNode := range root.FindAll("function_definition") {
			name := nameByLine[fnNode.StartLine()]
			if name == "" {
				continue
			}
			if reject := entryNullRejectParams(fnNode); len(reject) > 0 {
				nullReject[name] = reject
			}
		}

		for _, f := range funcs {
			checked := d.checkedVars(ifs, whiles, fors, dos, conds, switches, calls, returns, f)

			// var -> (callee, assignLine) for `v = callee(...)`.
			calleeOfVar := make(map[string]string)
			lineOfVar := make(map[string]int)
			for _, a := range assigns {
				if !funcLineRange(f, a.StartLine()) {
					continue
				}
				if v, callee := assignCallee(a); v != "" && callee != "" {
					calleeOfVar[v] = callee
					lineOfVar[v] = a.StartLine()
				}
			}
			for _, in := range inits {
				if !funcLineRange(f, in.StartLine()) {
					continue
				}
				if v, callee := assignCallee(in); v != "" && callee != "" {
					calleeOfVar[v] = callee
					lineOfVar[v] = in.StartLine()
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
					if callee, ok := calleeOfVar[v]; ok && passthroughReturnVar(v, lineOfVar[v], f, returns, ids, checked) {
						add(f.Name, callee)
					}
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}

	// Monotone fixpoint: a function is a passthrough allocator if it returns a
	// call to an unchecked-return API, to an allocator (built-in, declared, or
	// heuristic-matched), or to another passthrough allocator. The
	// apikb.IsAllocator term covers wrappers of heuristic-matched allocators
	// (e.g. `void *w(size_t n) { return my_alloc(n); }` where my_alloc is
	// matched by the "alloc" substring heuristic but is not in
	// uncheckedReturnAPIs) — without it, w would not be recognised as a
	// passthrough and calls to w would miss the unchecked-return check.
	passthrough := make(map[string]bool)
	changed := true
	for changed {
		changed = false
		for name, callees := range returnedSource {
			if passthrough[name] || apikb.IsNonNullReturning(name) {
				continue
			}
			for callee := range callees {
				if uncheckedReturnAPIs[callee] || passthrough[callee] || apikb.IsAllocator(callee) {
					passthrough[name] = true
					changed = true
					break
				}
			}
		}
	}
	return &funcSummaries{passthrough: passthrough, nullRejectParams: nullReject}, nil
}

// nullSafeFreeCalls are deallocators for which NULL is a defined no-op, so an
// unchecked allocation whose only consumer is one of them cannot misbehave.
// A generic deallocator (`obj_destroy(p)`, `buf_cleanup(p)`) is deliberately NOT
// here: it may dereference its argument, so passing a NULL allocation to it is a
// real defect.
var nullSafeFreeCalls = map[string]bool{"free": true, "cfree": true, "kfree": true}

// onlyFreedAfter reports whether every use of the assigned pointer variables
// after the allocation is a NULL-safe deallocation, with at least one such call.
// `p = malloc(n); free(p);` is the classic false positive: free(NULL) is a
// no-op, so the ignored failure cannot be observed (the round-2 benchmark's
// tp_sizeof_pointer reached the auto-confirmed tier as a CWE-252 finding this
// way). The allocation's own declarator/assignment is not a use. Any other
// occurrence — dereference, field/subscript, sizeof, another call, a return —
// disqualifies the suppression, so a macro that hides a dereference is not
// swallowed.
func onlyFreedAfter(vars []string, call parser.Node, f *db.Function, ids []parser.Node) bool {
	targets := make(map[string]bool, len(vars))
	for _, v := range vars {
		// Only a bare identifier can be judged: `*p = malloc(n)` stores into a
		// pointed-to location whose aliases this function cannot see.
		if v == "" || strings.ContainsAny(v, ".[>*") {
			return false
		}
		targets[v] = true
	}
	allocStmt := storeStatementOfCall(call)
	freed := 0
	for _, id := range ids {
		if !targets[id.Text()] || !funcLineRange(f, id.StartLine()) || id.StartLine() < call.StartLine() {
			continue
		}
		if allocStmt != nil && nodeContains(*allocStmt, id) {
			continue
		}
		if !nullSafeFreedArg(id) {
			return false
		}
		freed++
	}
	return freed > 0
}

// storeStatementOfCall returns the assignment/initializer whose right-hand side
// is the call, so only that statement's own identifiers are exempted from the
// use census. Nil when the call's value is not stored (a bare expression).
func storeStatementOfCall(call parser.Node) *parser.Node {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression", "init_declarator":
			return p
		case "parenthesized_expression", "cast_expression", "binary_expression",
			"argument_list", "call_expression", "field_expression", "subscript_expression":
			continue
		default:
			return nil
		}
	}
	return nil
}

// nullSafeFreedArg reports whether the identifier is passed directly (possibly
// parenthesised/cast) as the argument of a NULL-safe deallocator. A member,
// element, dereference or arithmetic argument is not the pointer itself, so it
// does not count.
func nullSafeFreedArg(id parser.Node) bool {
	for p := id.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "parenthesized_expression", "cast_expression":
			continue
		case "argument_list":
			call := p.Parent()
			if call == nil || call.Kind() != "call_expression" {
				return false
			}
			return nullSafeFreeCalls[extractCallName(*call)]
		default:
			return false
		}
	}
	return false
}

// passthroughReturnVar reports whether variable v, assigned at assignLine in f,
// is later returned by f without being null-checked or otherwise used in between.
// `void *x_malloc(n) { void *p = malloc(n); return p; }` is a passthrough
// allocator: the caller checks, so f's own unchecked-return call must not be
// flagged (and f itself becomes a source the caller must check). A use of v
// between the assignment and the return (e.g. `p[0] = 'x'`) is a genuine
// unchecked-use defect, so it must NOT count as a passthrough.
func passthroughReturnVar(v string, assignLine int, f *db.Function, returns, ids []parser.Node, checked map[string]bool) bool {
	if v == "" || checked[v] {
		return false
	}
	retLine := -1
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) || ret.StartLine() <= assignLine {
			continue
		}
		if returnedVar(ret) == v {
			retLine = ret.StartLine()
			break
		}
	}
	if retLine < 0 {
		return false
	}
	for _, id := range ids {
		if id.Text() != v || !funcLineRange(f, id.StartLine()) {
			continue
		}
		if id.StartLine() > assignLine && id.StartLine() < retLine {
			return false
		}
	}
	return true
}

// returnedVar returns the identifier a return statement returns (`return v`),
// else "" (for `return g()`, `return p->x`, `return NULL`, ...).
func returnedVar(ret parser.Node) string {
	for _, child := range ret.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

// assignCallee returns (varName, calleeName) for an assignment/initializer of the
// form `v = callee(...)` / `T v = callee(...)` (RHS possibly cast/parenthesised).
// It returns ("", "") for any other RHS shape.
func assignCallee(node parser.Node) (string, string) {
	lhs, rhs, ok := node.AssignParts()
	if !ok {
		return "", ""
	}
	v := assignedVariable(lhs)
	if v == "" {
		return "", ""
	}
	return v, calleeOfExpr(rhs)
}

// returnedCalleeName returns the called function name when a return statement
// directly returns a call (`return g(...)`), unwrapping casts/parentheses; else "".
func returnedCalleeName(ret parser.Node) string {
	for _, child := range ret.NamedChildren() {
		if name := calleeOfExpr(child); name != "" {
			return name
		}
	}
	return ""
}

// calleeOfExpr returns the called function name when expr is a call_expression
// possibly wrapped in casts/parentheses, else "".
func calleeOfExpr(expr parser.Node) string {
	switch expr.Kind() {
	case "call_expression":
		return extractCallName(expr)
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if name := calleeOfExpr(c); name != "" {
				return name
			}
		}
	}
	return ""
}
