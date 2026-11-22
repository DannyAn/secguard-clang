package evidence

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// functionPointerVarName pulls the variable name out of a function-pointer
// declarator text (`(*zmalloc_oom_handler)(size_t)` → "zmalloc_oom_handler").
func functionPointerVarName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 3 || s[0] != '(' || s[1] != '*' {
		return ""
	}
	s = s[2:]
	for i, c := range s {
		if c == ')' {
			return strings.TrimSpace(s[:i])
		}
	}
	return ""
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
		if insideSizeof(id) {
			continue
		}
		if isRebindTarget(id) {
			continue
		}
		if !nullSafeFreedArg(id) {
			return false
		}
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
