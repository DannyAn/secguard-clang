package evidence

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

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
// scanUsageTargets validates the assigned bare-local targets and finds the
// first rebind line. allUsesNullSafe and neverUsedAfter used to copy this
// prelude; they differ only in how they classify the remaining occurrences.
func scanUsageTargets(vars []string, call parser.Node, f *db.Function, ids []parser.Node, isLocal func(string) bool) (map[string]bool, *parser.Node, int, bool) {
	targets := make(map[string]bool, len(vars))
	for _, v := range vars {
		if v == "" || strings.ContainsAny(v, ".[>*") || !isLocal(v) {
			return nil, nil, 0, false
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
	return targets, allocStmt, rebindLine, true
}

func allUsesNullSafe(vars []string, call parser.Node, f *db.Function, ids []parser.Node, checked map[string]bool, sums *funcSummaries, retTypes map[string]string, isLocal func(string) bool) bool {
	targets, allocStmt, rebindLine, ok := scanUsageTargets(vars, call, f, ids, isLocal)
	if !ok {
		return false
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
