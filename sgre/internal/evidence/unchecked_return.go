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
				// Out-param allocators (asprintf/vasprintf/getline/getdelim):
				// the return value is a status code and a failed call leaves
				// the out-param NULL (glibc semantics). The defect's DIRECT
				// consequence is an in-function deref of that possibly-NULL
				// out-param (`asprintf(&p,...); p[0]=x;`). When the out-param
				// is only handed to callees — the NAT framework's
				// `asprintf(&err_msg,...); return fail(error, err_msg, ...)`
				// pattern — its NULL fate belongs to the null-deref chain (a
				// callee with a definition) or to the project's framework
				// contract (an external callee), never to a confirmed
				// unchecked-return verdict here.
				if outIdx, ok := apikb.IsOutParamAllocator(callee); ok {
					if v := outParamVar(call, outIdx); v != "" && !unguardedDerefAfter(v, call.StartLine(), f, ids, ifs) {
						continue
					}
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
						if checked[v] {
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
					//
					// Only function-local storage qualifies for the
					// never-observably-used judgement: a global/external
					// target's real uses live in other functions and are
					// invisible here, so they must keep the event.
					isLocalTarget := func(v string) bool {
						if _, ok := localDeclLines[v]; ok {
							return true
						}
						return paramsByLine[f.StartLine][v]
					}
					if neverUsedAfter(vars, call, f, ids, isLocalTarget) {
						continue
					}
					// Consumer census (AND semantics): every observable use of
					// the stored result after the call is NULL-safe — free,
					// sizeof, a rebind, or an argument to a consumer whose that
					// parameter is null-safe (see nullSafeConsumerArg). A NULL
					// result then cannot misbehave anywhere in this function, so
					// the unchecked-return event is a false positive even though
					// the value itself is never compared (report shape A2:
					// `(void)filter_add(f, key)` with entry-guarded consumers).
					// One unsafe use — a dereference, an unguarded callee — keeps
					// the event, so a value validated at one consumer and
					// dereferenced at another stays reported.
					if allUsesNullSafe(vars, call, f, ids, checked, summaries, retTypes, isLocalTarget) {
						continue
					}
					// Field escape: the target is a member of a local struct that
					// is later passed (as `s` / `&s`) to a function validating
					// exactly that member path against NULL with a failure return
					// (report shape B: `para->user_filter = import_strdup(...)` +
					// `para_is_valid(&para)`). The field's NULL is handled
					// downstream by the shared validator, so the event on the
					// field store is noise.
					if fieldValidatedElsewhere(vars, call.StartLine(), f, calls, summaries.fieldNullChecks, isLocalTarget) {
						continue
					}
				}

				props := map[string]string{
					"function":       extractCallName(call),
					"expression":     call.OriginalText(),
					"category":       "unchecked_return",
					"contract_known": strconv.FormatBool(contractKnown),
				}
				// A result whose only observable use is a `(void)` cast is
				// deliberately discarded: the failure cannot be observed, but the
				// lead stays (name-heuristic contract) with a discard@ fact so the
				// AI dismisses from the hint without a source read.
				if vars := assignedVarsOfCall(call); len(vars) > 0 && resultVoidDiscarded(vars, call, f, ids) {
					props["consumed"] = "discard"
				}
				if emitEvent(ctx, d.store, d.logger, "UNCHECKED_RETURN", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, props) {
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

// allUsesNullSafe reports whether every observable use of the assigned
// variables after the call is NULL-safe, so a NULL result cannot misbehave
// anywhere in the function. Safe uses are a NULL-safe deallocation (free),
// a sizeof operand, a rebind (ends the value's window), and an argument
// passed to a consumer whose that parameter is null-safe under the channel
// rules in nullSafeConsumerArg. Any other occurrence — a dereference, an
// argument to an unguarded callee, a return — disqualifies (AND semantics):
// a value validated at some consumers and dereferenced at another keeps its
// event. Only bare local (or parameter) identifiers qualify: a global
// target's real uses live in other functions and are invisible here, and a
// field/pointed-to target is the fieldValidatedElsewhere escape's business,
// not a consumer census.
func allUsesNullSafe(vars []string, call parser.Node, f *db.Function, ids []parser.Node, checked map[string]bool, sums *funcSummaries, retTypes map[string]string, isLocal func(string) bool) bool {
	targets := make(map[string]bool, len(vars))
	for _, v := range vars {
		if v == "" || strings.ContainsAny(v, ".[>*") || !isLocal(v) {
			return false
		}
		targets[v] = true
	}
	allocStmt := storeStatementOfCall(call)
	rebindLine := 0
	for _, id := range ids {
		if !targets[id.Text()] || !funcLineRange(f, id.StartLine()) || id.StartLine() <= call.StartLine() {
			continue
		}
		if allocStmt != nil && nodeContains(*allocStmt, id) {
			continue
		}
		if isRebindTarget(id) && (rebindLine == 0 || id.StartLine() < rebindLine) {
			rebindLine = id.StartLine()
		}
	}
	for _, id := range ids {
		if !targets[id.Text()] || !funcLineRange(f, id.StartLine()) || id.StartLine() < call.StartLine() {
			continue
		}
		if allocStmt != nil && nodeContains(*allocStmt, id) {
			continue
		}
		if rebindLine > 0 && id.StartLine() >= rebindLine {
			continue
		}
		if insideSizeof(id) || isRebindTarget(id) || nullSafeFreedArg(id) {
			continue
		}
		if nullSafeConsumerArg(id, checked, sums, retTypes) {
			continue
		}
		return false
	}
	return true
}

// nullSafeConsumerArg reports whether the identifier occurrence is passed
// (bare, possibly cast/parenthesised) as argument i of a call whose parameter
// i is null-safe in the callee's body, under the channel rules that keep the
// polarity traps reportable:
//
//   - the callee returns void: it handles a NULL internally (the
//     `void release_entry(Entry *e) { if (!e) return; ... }` consumer), so
//     there is no result to check and no error to propagate;
//   - the call's result is checked — inline, or via a variable that is itself
//     checked: the caller RELIES on a failure sentinel, so the callee must
//     actually reject NULL with a failure return (nullRejectParams). A callee
//     that answers success on NULL turns the caller's check into a false
//     sense of safety, so the event must stay;
//   - the result is discarded — `(void)f(p)`, a bare statement, a variable
//     that is stored but never checked: the caller relies on nothing, so the
//     callee merely has to not dereference the NULL (paramNullSafe). This is
//     report shape A2: `(void)filter_add(f, key)` with an entry-guarded
//     consumer whose int result the caller deliberately drops.
func nullSafeConsumerArg(id parser.Node, checked map[string]bool, sums *funcSummaries, retTypes map[string]string) bool {
	var list *parser.Node
	for p := id.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "argument_list" {
			list = p
			break
		}
		if p.Kind() != "parenthesized_expression" && p.Kind() != "cast_expression" {
			return false
		}
	}
	if list == nil {
		return false
	}
	call := list.Parent()
	if call == nil || call.Kind() != "call_expression" {
		return false
	}
	callee := extractCallName(*call)
	idx := -1
	for i, arg := range list.NamedChildren() {
		if nodeContains(arg, id) {
			idx = i
			break
		}
	}
	if idx < 0 || !sums.paramNullSafe[callee][idx] {
		return false
	}
	if voidReturning(retTypes, callee) {
		return true
	}
	if callResultChecked(*call) {
		return sums.nullRejectParams[callee][idx]
	}
	for _, v := range assignedVarsOfCall(*call) {
		if checked[v] {
			return sums.nullRejectParams[callee][idx]
		}
	}
	return true
}

// fieldValidatedElsewhere reports whether every assigned target is a member
// of a local struct whose containing value is passed (as `s` or `&s`) to a
// function that validates exactly that member path against NULL with a
// failure return (fieldNullChecks). Report shape B: `para->user_filter =
// import_strdup(flt); ... if (para_is_valid(&para) != 0) return -1;` — the
// field's NULL is handled downstream by the shared validator, so the
// unchecked-return event on the field store is a false positive.
func fieldValidatedElsewhere(vars []string, assignLine int, f *db.Function, calls []parser.Node, fieldChecks map[string]map[string]bool, isLocal func(string) bool) bool {
	if len(fieldChecks) == 0 || len(vars) == 0 {
		return false
	}
	for _, v := range vars {
		if !fieldValidated(v, assignLine, f, calls, fieldChecks, isLocal) {
			return false
		}
	}
	return true
}

// fieldValidated checks one assigned location against the downstream
// validators. The base of the member path must be a local (or parameter) so
// the passing call's argument really is that storage, and the validating call
// must come after the field store.
func fieldValidated(v string, assignLine int, f *db.Function, calls []parser.Node, fieldChecks map[string]map[string]bool, isLocal func(string) bool) bool {
	base := locationBase(v)
	if base == "" || !isLocal(base) {
		return false
	}
	field := strings.TrimPrefix(strings.TrimPrefix(v[len(base):], "->"), ".")
	if field == "" {
		return false
	}
	for _, c := range calls {
		if c.StartLine() <= assignLine || !funcLineRange(f, c.StartLine()) {
			continue
		}
		if !fieldChecks[extractCallName(c)][field] {
			continue
		}
		for _, arg := range getCallArgs(c) {
			switch stripCastsAndParens(arg.Text()) {
			case base, "&" + base:
				return true
			}
		}
	}
	return false
}

// paramAliases returns the local variables that merely rename a parameter
// through a cast or plain binding (`filter_t *ft = (filter_t *)f;`,
// `q = p;`), keyed by the alias name. Only names whose EVERY binding resolves
// to the same parameter qualify: a name ever rebound to something else stops
// tracking the parameter. Guards on such an alias (`if (ft == NULL) return
// -1;`) validate the parameter itself, which is how the entry-guard and
// null-safe summaries see through the `void *`-to-typed-pointer rebinding
// idiom of the report's filter_add shape.
func paramAliases(fnNode parser.Node) map[string]string {
	body := fnNode.FindFirst("compound_statement")
	if body == nil {
		return nil
	}
	params := paramPositions(fnNode)
	if len(params) == 0 {
		return nil
	}
	paramSet := make(map[string]bool, len(params))
	for _, p := range params {
		if p != "" {
			paramSet[p] = true
		}
	}
	bindings := make(map[string][]string)
	record := func(lhs, rhs parser.Node) {
		// assignedVariable unwraps the declarator shapes a binding can take:
		// a bare identifier (`q = p`) or a pointer declarator
		// (`filter_t *ft = (filter_t *)f`).
		name := assignedVariable(lhs)
		if name == "" || paramSet[name] {
			return
		}
		target, ok := bareIdentifierOf(rhs)
		if !ok || !paramSet[target] {
			bindings[name] = append(bindings[name], "")
			return
		}
		bindings[name] = append(bindings[name], target)
	}
	for _, node := range body.FindAll("init_declarator") {
		if lhs, rhs, ok := node.AssignParts(); ok {
			record(lhs, rhs)
		}
	}
	for _, node := range body.FindAll("assignment_expression") {
		if lhs, rhs, ok := node.AssignParts(); ok {
			record(lhs, rhs)
		}
	}
	aliases := make(map[string]string)
	for alias, names := range bindings {
		first := names[0]
		if first == "" {
			continue
		}
		for _, n := range names[1:] {
			if n != first {
				first = ""
				break
			}
		}
		if first != "" {
			aliases[alias] = first
		}
	}
	return aliases
}

// bareIdentifierOf strips casts/parentheses from expr and returns its text
// when the result is a bare identifier.
func bareIdentifierOf(expr parser.Node) (string, bool) {
	switch expr.Kind() {
	case "identifier":
		return expr.Text(), true
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if name, ok := bareIdentifierOf(c); ok {
				return name, true
			}
		}
	}
	return "", false
}

// entryNullRejectParams returns the 0-based parameter indices a function
// null-safely rejects at entry: a top-level `if` whose NULL-direction branch
// returns (`if (p == NULL) return -1;`, `if (!e) return;`, `if (!p) return 0;`
// all reject parameter p — the branch taken when p is NULL exits the function
// before any dereference). The polarity matters — `if (p != NULL) { ... } else
// { return; }` rejects p too, while `if (p != NULL) return 0;` does not (the
// p == NULL path falls through). A BARE or success return counts: a NULL-safe
// consumer handles NULL internally (`void release_entry(Entry *e) { if (!e)
// return; ... }`), so the caller's unchecked return is a false positive even
// though there is no failure sentinel for the caller to observe. A guard on a
// cast alias of the parameter (`filter_t *ft = (filter_t *)f; if (ft == NULL)
// return -1;`) rejects the parameter too.
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
	aliases := paramAliases(fnNode)
	var out map[int]bool
	mark := func(vars []string) {
		for _, v := range vars {
			name := v
			if param, aliased := aliases[v]; aliased {
				name = param
			}
			i, ok := index[name]
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
		if cons := stmt.ChildByFieldName("consequence"); cons != nil && branchReturns(*cons) {
			mark(parser.NullCheckedVars(*cond))
		}
		if alt := stmt.ChildByFieldName("alternative"); alt != nil && branchReturns(*alt) {
			mark(parser.GuardedNonnullVars(*cond))
		}
	}
	return out
}

// branchReturns reports whether a branch body exits the function on the NULL
// path in a way that makes the argument null-safe: a bare `return;` (a void
// consumer handles NULL internally — `void release_entry(Entry *e) { if (!e)
// return; ... }`), or a failure sentinel (`return -1;` / `return NULL;` /
// `return IDM_ERR;`, which the caller can observe). A success return
// (`return 0;` / `return false;`) is NOT a guard: the caller's `ret != 0` test
// cannot distinguish a NULL argument from success, so the NULL is unhandled.
// The polarity of WHICH branch is the NULL branch is decided by
// NullCheckedVars/GuardedNonnullVars in the caller.
func branchReturns(branch parser.Node) bool {
	for _, ret := range branch.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			return true
		}
		text := stripCastsAndParens(children[0].Text())
		if text == "" || text == "0" || text == "false" || text == "FALSE" {
			continue
		}
		return true
	}
	return false
}

// paramNullSafeParams returns the 0-based parameter indices that are NULL-safe
// in the function's body: a NULL argument cannot be dereferenced there. That
// is the union of
//
//   - entry rejection (entryNullRejectParams, cast-alias aware): a NULL
//     argument exits at the guard before any dereference, and
//   - positive body guards: at least one `if (p != NULL)`-style guard exists,
//     and every dereference of the parameter (or of a cast alias of it) is
//     dominated by such a guard's non-null branch.
//
// A function with no guard and no dereference (e.g. one that merely stashes
// the pointer into a global) is deliberately NOT null-safe: the value escapes
// unchecked, and the caller cannot see what happens to it.
func paramNullSafeParams(fnNode parser.Node) map[int]bool {
	safe := entryNullRejectParams(fnNode)
	body := fnNode.FindFirst("compound_statement")
	if body == nil {
		return safe
	}
	params := paramPositions(fnNode)
	if len(params) == 0 {
		return safe
	}
	aliases := paramAliases(fnNode)
	paramIndex := func(name string) int {
		for i, p := range params {
			if p == name {
				return i
			}
		}
		return -1
	}
	for _, param := range params {
		if param == "" {
			continue
		}
		names := map[string]bool{param: true}
		for alias, p := range aliases {
			if p == param {
				names[alias] = true
			}
		}
		guarded := false
		for _, ifn := range body.FindAll("if_statement") {
			cond := ifn.ChildByFieldName("condition")
			if cond == nil {
				continue
			}
			for _, g := range parser.GuardedNonnullVars(*cond) {
				if names[g] {
					guarded = true
					break
				}
			}
			if guarded {
				break
			}
		}
		if !guarded {
			continue
		}
		allGuarded := true
		for _, deref := range paramDerefPoints(*body, names) {
			if !guardedByIf(deref, names) {
				allGuarded = false
				break
			}
		}
		if allGuarded {
			idx := paramIndex(param)
			if idx >= 0 {
				if safe == nil {
					safe = make(map[int]bool)
				}
				safe[idx] = true
			}
		}
	}
	return safe
}

// paramDerefPoints returns the nodes in body that dereference any of the
// given names: `n->f`, `n[i]`, `(*n)` — a field/subscript whose base (after
// cast/paren stripping) is one of the names, or a `*` pointer_expression of
// one of them. A dereference inside a guard condition (`if (p->count > 0)`)
// counts too; guardedByIf decides whether it is actually guarded.
func paramDerefPoints(body parser.Node, names map[string]bool) []parser.Node {
	var out []parser.Node
	for _, kind := range []string{"field_expression", "subscript_expression"} {
		for _, n := range body.FindAll(kind) {
			children := n.NamedChildren()
			if len(children) == 0 {
				continue
			}
			if base, ok := bareIdentifierOf(children[0]); ok && names[base] {
				out = append(out, n)
			}
		}
	}
	for _, n := range body.FindAll("pointer_expression") {
		if !strings.HasPrefix(strings.TrimSpace(n.Text()), "*") {
			continue // & — address-of, not a dereference
		}
		for _, c := range n.NamedChildren() {
			if base, ok := bareIdentifierOf(c); ok && names[base] {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// guardedByIf reports whether the dereference node is dominated by a null
// guard on one of names: walking up the ancestors, an if_statement whose
// consequence contains the node and whose condition establishes non-null
// (`if (p != NULL) { ... p->f ... }`), or whose alternative contains the node
// and whose condition establishes NULL (`if (p == NULL) { ... } else { p->f }`).
func guardedByIf(deref parser.Node, names map[string]bool) bool {
	for p := deref.Parent(); p != nil; p = p.Parent() {
		if p.Kind() != "if_statement" {
			continue
		}
		cond := p.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if cons := p.ChildByFieldName("consequence"); cons != nil && nodeContains(*cons, deref) {
			for _, g := range parser.GuardedNonnullVars(*cond) {
				if names[g] {
					return true
				}
			}
		}
		if alt := p.ChildByFieldName("alternative"); alt != nil && nodeContains(*alt, deref) {
			for _, g := range parser.NullCheckedVars(*cond) {
				if names[g] {
					return true
				}
			}
		}
	}
	return false
}

// fieldNullChecksOfBody returns the member paths a function validates against
// NULL at a top-level guard with a failure/bare return:
// `if (p->user_filter == NULL || p->dst_name == NULL) return -1;` yields
// {"user_filter", "dst_name"}. Only NULL comparisons (`== NULL`, `!p->f`,
// bare pointer truthiness) contribute — a numeric comparison on a member
// (`p->count > 0`) validates nothing about NULL. The base name is dropped so
// a caller holding a differently-named struct still matches; nested paths
// keep their relative shape (`p->a->b` -> "a->b").
func fieldNullChecksOfBody(fnNode parser.Node) map[string]bool {
	body := fnNode.FindFirst("compound_statement")
	if body == nil {
		return nil
	}
	var out map[string]bool
	add := func(loc string) {
		base := locationBase(loc)
		if base == "" {
			return
		}
		rest := strings.TrimPrefix(strings.TrimPrefix(loc[len(base):], "->"), ".")
		if rest == "" || strings.ContainsAny(rest, "(<&*+-") {
			return
		}
		if out == nil {
			out = make(map[string]bool)
		}
		out[rest] = true
	}
	for _, stmt := range body.NamedChildren() {
		if stmt.Kind() != "if_statement" {
			continue
		}
		cons := stmt.ChildByFieldName("consequence")
		if cons == nil || !branchReturns(*cons) {
			continue
		}
		cond := stmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		for _, b := range cond.FindAll("binary_expression") {
			if parser.BinaryOperator(b) != "==" {
				continue
			}
			children := b.NamedChildren()
			if len(children) < 2 {
				continue
			}
			var other parser.Node
			switch {
			case parser.IsNullOperand(children[0]):
				other = children[1]
			case parser.IsNullOperand(children[1]):
				other = children[0]
			default:
				continue
			}
			switch other.Kind() {
			case "field_expression", "subscript_expression", "pointer_expression":
				add(other.Text())
			}
		}
		for _, v := range bareConditionVars(cond) {
			add(v)
		}
	}
	return out
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

// insideVoidCast reports whether an identifier is the operand of a cast to
// void (`(void)p`) — the programmer's explicit "discard this value"
// annotation. It walks parenthesized expressions but stops at the statement
// boundary, so a `(void)` on an unrelated expression cannot swallow a later use.
func insideVoidCast(id parser.Node) bool {
	for p := id.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "cast_expression":
			for _, c := range p.NamedChildren() {
				if c.Kind() == "type_descriptor" {
					return typeSpelling(c) == "void"
				}
			}
			return false
		case "parenthesized_expression":
			continue
		case "expression_statement", "function_definition":
			return false
		}
	}
	return false
}

// resultVoidDiscarded reports whether an assigned result is consumed ONLY by
// explicit `(void)` casts after the call (with free/sizeof/rebind occurrences
// also tolerated). It is distinct from neverUsedAfter's dead store (no
// occurrence at all): the value IS discarded deliberately, so the failure
// cannot be observed, but the event stays as a lead carrying a `discard@` fact
// so the AI dismisses from the hint instead of reading the source to find the
// `(void)p` (round3 idm_new_idmgr).
func resultVoidDiscarded(vars []string, call parser.Node, f *db.Function, ids []parser.Node) bool {
	targets := make(map[string]bool, len(vars))
	for _, v := range vars {
		if v == "" || strings.ContainsAny(v, ".[>*") {
			return false
		}
		targets[v] = true
	}
	discarded := false
	for _, id := range ids {
		if !targets[id.Text()] || !funcLineRange(f, id.StartLine()) || id.StartLine() <= call.StartLine() {
			continue
		}
		if insideSizeof(id) || isRebindTarget(id) || nullSafeFreedArg(id) {
			continue
		}
		if insideVoidCast(id) {
			discarded = true
			continue
		}
		return false // a real observable use — not a pure discard
	}
	return discarded
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

// voidReturning reports whether the indexed function's declared return type is
// exactly `void` (no result to check). Used by nullSafeConsumerArg to recognise
// a void consumer whose null-safe parameter handles a NULL argument
// internally, so the source call's unchecked return is a false positive. An
// unknown/empty type stays non-void (conservative) so a missing return-type
// cannot silently widen the suppression.
func voidReturning(retTypes map[string]string, name string) bool {
	if retTypes == nil {
		return false
	}
	return strings.TrimSpace(retTypes[name]) == "void"
}

// funcSummaries bundles the cross-function facts the detector derives from
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
	// paramNullSafe maps a function name to the 0-based indices of the
	// parameters that are NULL-safe in its body: a NULL argument cannot be
	// dereferenced there (see paramNullSafeParams). Superset of
	// nullRejectParams — rejecting at entry is one way to be null-safe, while
	// a positive guard `if (p != NULL) { ... }` protects the dereferences
	// without exposing a failure the caller could observe.
	paramNullSafe map[string]map[int]bool
	// fieldNullChecks maps a function name to the member paths it validates
	// against NULL at a top-level guard with a failure return (see
	// fieldNullChecksOfBody). A caller that stores an allocation into a local
	// struct field and then passes the struct to such a validator has the
	// field's NULL handled downstream.
	fieldNullChecks map[string]map[string]bool
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
	nullSafe := make(map[string]map[int]bool)
	fieldChecks := make(map[string]map[string]bool)

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
			if safe := paramNullSafeParams(fnNode); len(safe) > 0 {
				nullSafe[name] = safe
			}
			if checks := fieldNullChecksOfBody(fnNode); len(checks) > 0 {
				fieldChecks[name] = checks
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
	return &funcSummaries{passthrough: passthrough, nullRejectParams: nullReject, paramNullSafe: nullSafe, fieldNullChecks: fieldChecks}, nil
}

// nullSafeFreeCalls are deallocators for which NULL is a defined no-op, so an
// unchecked allocation whose only consumer is one of them cannot misbehave.
// A generic deallocator (`obj_destroy(p)`, `buf_cleanup(p)`) is deliberately NOT
// here: it may dereference its argument, so passing a NULL allocation to it is a
// real defect.
var nullSafeFreeCalls = map[string]bool{"free": true, "cfree": true, "kfree": true}

// neverUsedAfter reports whether the assigned pointer variables' stored value
// is never observably used in the function, with every in-scope occurrence
// being either a NULL-safe deallocation or none at all:
//
//   - `p = malloc(n); free(p);` — free(NULL) is a no-op, so the ignored
//     failure cannot be observed (the classic tp_sizeof_pointer false
//     positive that once reached the auto-confirmed tier).
//   - `p = malloc(n);` with no later occurrence — a dead store: the value is
//     never consumed at all. The accompanying leak, if any, is the
//     resource-leak detector's domain, not an unchecked return.
//   - a rebinding occurrence (`p = malloc(16); p = malloc(32); free(p);`)
//     kills the old value at the rebind line: occurrences from there on
//     belong to the new value, so the old allocation's window ends at the
//     first rebind. `free(p); p = &fallback;` likewise only ever freed the
//     stored value.
//   - a sizeof operand (`sizeof(*p)`, `sizeof(p->len)`, `sizeof(p[0])`) is an
//     unevaluated compile-time size query, not a use.
//
// Only function-local targets qualify (isLocal): a global/external storage's
// uses are cross-function and invisible here. The allocation's own
// declarator/assignment is not a use. Any other occurrence — dereference,
// field/subscript write or read, another call, a return — disqualifies the
// suppression, so a macro that hides a dereference is not swallowed.
func neverUsedAfter(vars []string, call parser.Node, f *db.Function, ids []parser.Node, isLocal func(string) bool) bool {
	targets := make(map[string]bool, len(vars))
	for _, v := range vars {
		// Only a bare local identifier can be judged: `*p = malloc(n)` stores
		// into a pointed-to location, and `obj->f = malloc(n)` into a field,
		// whose aliases this function cannot see.
		if v == "" || strings.ContainsAny(v, ".[>*") || !isLocal(v) {
			return false
		}
		targets[v] = true
	}
	allocStmt := storeStatementOfCall(call)
	rebindLine := 0
	for _, id := range ids {
		if !targets[id.Text()] || !funcLineRange(f, id.StartLine()) || id.StartLine() <= call.StartLine() {
			continue
		}
		if allocStmt != nil && nodeContains(*allocStmt, id) {
			continue
		}
		if isRebindTarget(id) && (rebindLine == 0 || id.StartLine() < rebindLine) {
			rebindLine = id.StartLine()
		}
	}
	freed := 0
	for _, id := range ids {
		if !targets[id.Text()] || !funcLineRange(f, id.StartLine()) || id.StartLine() < call.StartLine() {
			continue
		}
		if allocStmt != nil && nodeContains(*allocStmt, id) {
			continue
		}
		if rebindLine > 0 && id.StartLine() >= rebindLine {
			continue
		}
		if insideSizeof(id) {
			continue
		}
		if isRebindTarget(id) {
			continue
		}
		if !nullSafeFreedArg(id) {
			return false
		}
		freed++
	}
	return true
}

// isRebindTarget reports whether the identifier occurrence is the bare storage
// location a new value is being written to — the left side of an assignment
// (`p = ...`), or a declaration's own declarator. Such an occurrence rebinds
// the name instead of using the previously stored value. A write THROUGH the
// pointer (`p[0] = 1`, `p->len = 1`, `*p = 1`) is a use of the stored pointer
// value, not a rebind, so only a pure-identifier left side qualifies.
func isRebindTarget(id parser.Node) bool {
	p := id.Parent()
	if p == nil {
		return false
	}
	switch p.Kind() {
	case "assignment_expression":
		children := p.NamedChildren()
		return len(children) > 0 && children[0].Kind() == "identifier" && children[0].Text() == id.Text()
	case "init_declarator":
		children := p.NamedChildren()
		return len(children) > 0 && nodeContains(children[0], id)
	}
	return false
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

// outParamVar returns the variable an out-param-allocator call writes into
// (`asprintf(&err_msg, ...)` → "err_msg"): the OutParamIdx argument with
// `&`/parentheses stripped.
func outParamVar(call parser.Node, idx int) string {
	args := getCallArgs(call)
	if idx >= len(args) {
		return ""
	}
	inner := args[idx]
	for {
		switch inner.Kind() {
		case "parenthesized_expression":
			kids := inner.NamedChildren()
			if len(kids) == 0 {
				return ""
			}
			inner = kids[0]
		case "pointer_expression":
			if !strings.HasPrefix(strings.TrimSpace(inner.Text()), "&") {
				return ""
			}
			kids := inner.NamedChildren()
			if len(kids) == 0 {
				return ""
			}
			inner = kids[0]
		default:
			if inner.Kind() == "identifier" {
				return inner.Text()
			}
			return ""
		}
	}
}

// unguardedDerefAfter reports whether varName is dereferenced in f after line
// `after` without a dominating NULL check. Only the DIRECT consequence an
// unchecked out-param-allocator return can have in this function counts: a
// `*v` / `v->f` / `v[i]` with no `if (v == NULL) return` / `if (!v) return` /
// `if (v != NULL) { ... }` / `if (v) { ... }` covering it.
func unguardedDerefAfter(varName string, after int, f *db.Function, ids, ifs []parser.Node) bool {
	for _, id := range ids {
		// ids spans the whole FILE — a same-named variable in a sibling
		// function (the NAT api_modules handlers all share `err_msg`) must
		// not count as this function's deref.
		if id.Text() != varName || id.StartLine() <= after || !funcLineRange(f, id.StartLine()) {
			continue
		}
		p := id.Parent()
		if p == nil {
			continue
		}
		isDeref := false
		switch p.Kind() {
		case "pointer_expression":
			isDeref = strings.HasPrefix(strings.TrimSpace(p.Text()), "*")
		case "field_expression", "subscript_expression":
			kids := p.NamedChildren()
			isDeref = len(kids) > 0 && kids[0].Kind() == "identifier" && kids[0].Text() == varName
		}
		if isDeref && !derefGuardedByNullCheck(f, varName, p.StartLine(), ifs) {
			return true
		}
	}
	return false
}

// derefGuardedByNullCheck reports whether a NULL check on varName dominates
// the dereference at derefLine: an early-exit `if (v == NULL)` / `if (!v)`
// before it, or a positive `if (v != NULL)` / `if (v)` whose consequence
// contains it.
func derefGuardedByNullCheck(f *db.Function, varName string, derefLine int, ifs []parser.Node) bool {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) || ifNode.StartLine() >= derefLine {
			continue
		}
		cond := ifNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		for _, v := range parser.NullCheckedVars(*cond) {
			if v == varName && ifConsequenceExits(ifNode) {
				return true
			}
		}
		for _, v := range parser.GuardedNonnullVars(*cond) {
			if v == varName {
				if cons := ifNode.ChildByFieldName("consequence"); cons != nil && derefLine >= cons.StartLine() && derefLine <= cons.EndLine() {
					return true
				}
			}
		}
	}
	return false
}

// ifConsequenceExits reports whether an if statement's consequence always
// leaves the function/loop (return / goto / break / continue).
func ifConsequenceExits(ifNode parser.Node) bool {
	cons := ifNode.ChildByFieldName("consequence")
	if cons == nil {
		return false
	}
	for _, stmt := range cons.NamedChildren() {
		switch stmt.Kind() {
		case "return_statement", "goto_statement", "break_statement", "continue_statement":
			return true
		}
	}
	return false
}
