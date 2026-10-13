package planner

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// contractCtx captures the per-function facts the nullable-source filter needs
// to recognise two "not really nullable" shapes that the event-based source
// model cannot see on its own:
//
//   - a variable that merely ALIASES a parameter (a copy or cast of it) must be
//     converged by the same "parameter has no proven nullable caller argument"
//     rule as a direct dereference of that parameter. The event model keys the
//     caller_null source by the PARAMETER name, so a derived variable escapes
//     the rule and surfaces as a false positive (`t = p; t->f`). This is
//     type-agnostic: an ordinary `T *` parameter behaves the same way.
//
//   - an opaque `void *` parameter dereferenced by contract: IPC / callback /
//     message handlers receive an untyped framework buffer and immediately
//     cast it (or extract it through an accessor) and dereference it without a
//     NULL check, because the framework guarantees it is non-null. A void*
//     parameter that is NEVER compared against NULL anywhere in the body is
//     the strongest available signal for this convention, so a value derived
//     from it (directly, through a cast, or through an unknown external
//     accessor call) is treated as non-null by contract.
//
// The struct is built once per candidate function (only functions with
// candidates are parsed), so the AST walks are bounded by the candidate set.
type contractCtx struct {
	// voidParams are the void*/const void* parameters the function never
	// null-checks and never returns (a passthrough wrapper is not a contract
	// dereference).
	voidParams map[string]bool
	// assigns indexes every assignment/initializer in the body by target name,
	// so a variable's value can be traced back to its parameter root.
	assigns map[string][]contractAssign
}

type contractAssign struct {
	line int
	rhs  parser.Node
}

// contractDepth bounds the value-chain walk (alias/cast/arithmetic hops and
// accessor-call hops) so a long or cyclic assignment graph cannot recurse
// without bound.
const contractDepth = 4

// buildContractCtx resolves the contract facts for one function.
func buildContractCtx(fn *db.Function, root, body parser.Node) *contractCtx {
	cc := &contractCtx{
		voidParams: map[string]bool{},
		assigns:    collectContractAssigns(body),
	}
	for p := range voidPtrParamsOf(fn, root) {
		if bodyNullChecksVar(body, p) || bodyReturnsVar(body, p) {
			continue
		}
		cc.voidParams[p] = true
	}
	return cc
}

// paramAliasUnproven reports whether v is a pure alias (copy / cast / arithmetic)
// of one or more parameters whose only null source is an UNPROVEN caller_null
// argument. Such a parameter is an analyzer limitation, not evidence the caller
// can pass NULL, so the derived dereference must be converged exactly like the
// direct `p->f` case.
func (cc *contractCtx) paramAliasUnproven(v string, line int, models *nullModel) bool {
	if cc == nil || models == nil {
		return false
	}
	roots := map[string]bool{}
	if !cc.aliasRoots(v, line, 0, roots) || len(roots) == 0 {
		return false
	}
	for r := range roots {
		if !models.onlyUnprovenCallerNullSources(r) {
			return false
		}
	}
	return true
}

// aliasRoots walks a value-preserving assignment chain (`v = x`, `v = (T*)x`)
// and collects the parameter/leaf variables it terminates at. It returns false
// when the chain reaches a construct that does not merely copy a value (an
// accessor call, a dereference, a field read), because then the value is not a
// pure alias and the unproven-parameter rule must not apply.
func (cc *contractCtx) aliasRoots(name string, line, depth int, out map[string]bool) bool {
	if depth > contractDepth {
		return false
	}
	a := cc.lastAssignBefore(name, line)
	if a == nil {
		out[name] = true
		return true
	}
	switch a.rhs.Kind() {
	case "identifier":
		return cc.aliasRoots(a.rhs.Text(), a.line, depth+1, out)
	case "parenthesized_expression", "cast_expression":
		op, ok := aliasOperand(a.rhs)
		if !ok || op.Kind() != "identifier" {
			return false
		}
		return cc.aliasRoots(op.Text(), a.line, depth+1, out)
	}
	return false
}

// contractDerived reports whether v's value comes, without a NULL check, from a
// void* parameter used by contract: directly, through casts / pointer
// arithmetic, or through an external accessor call whose argument is such a
// parameter. A value produced by an allocator, a known maybe-null libc function
// (malloc, getenv, ...), or an UNKNOWN external call that the null model flags
// with an external_call source is deliberately NOT contract-derived — those
// might genuinely return NULL and must stay reportable (RISK-2).
func (cc *contractCtx) contractDerived(v string, line int, models *nullModel) bool {
	if cc == nil {
		return false
	}
	return cc.derivedName(v, line, 0, models)
}

func (cc *contractCtx) derivedName(name string, line, depth int, models *nullModel) bool {
	if depth > contractDepth {
		return false
	}
	if cc.voidParams[name] {
		return true
	}
	a := cc.lastAssignBefore(name, line)
	if a == nil {
		return false
	}
	// If the variable is assigned a call result AND the null model recorded an
	// external_call source for it, the accessor might return NULL — do not
	// treat the value as contract-derived. This prevents dismissing a genuine
	// null-deref through an accessor that can fail (RISK-2).
	if models != nil && models.hasExternalCallSource(name) && rhsContainsCall(a.rhs) {
		return false
	}
	return cc.derivedExpr(a.rhs, a.line, depth+1, models)
}

func (cc *contractCtx) derivedExpr(expr parser.Node, line, depth int, models *nullModel) bool {
	if depth > contractDepth {
		return false
	}
	switch expr.Kind() {
	case "identifier":
		return cc.derivedName(expr.Text(), line, depth, models)
	case "parenthesized_expression":
		for _, c := range expr.NamedChildren() {
			if cc.derivedExpr(c, line, depth, models) {
				return true
			}
		}
	case "cast_expression":
		if op, ok := aliasOperand(expr); ok {
			return cc.derivedExpr(op, line, depth, models)
		}
	case "pointer_expression":
		for _, c := range expr.NamedChildren() {
			if cc.derivedExpr(c, line, depth, models) {
				return true
			}
		}
	case "binary_expression":
		if op := parser.BinaryOperator(expr); op == "+" || op == "-" {
			for _, c := range expr.NamedChildren() {
				if cc.derivedExpr(c, line, depth, models) {
					return true
				}
			}
		}
	case "call_expression":
		name := callName(expr)
		if name == "" || isAllocatorCall(name) || apikb.IsKnownNullableReturn(name) {
			return false
		}
		for _, arg := range callArgs(expr) {
			if cc.derivedExpr(arg, line, depth, models) {
				return true
			}
		}
	}
	return false
}

// rhsContainsCall reports whether expr is or contains a call_expression (an
// accessor call whose result might be NULL). Used to gate the contract
// derivation: a value from an external call that the null model flagged with an
// external_call source must not be treated as contract-non-null.
func rhsContainsCall(expr parser.Node) bool {
	if expr.Kind() == "call_expression" {
		return true
	}
	for _, c := range expr.NamedChildren() {
		if rhsContainsCall(c) {
			return true
		}
	}
	return false
}

// lastAssignBefore returns the last assignment to name at or before line, or nil.
func (cc *contractCtx) lastAssignBefore(name string, line int) *contractAssign {
	sites := cc.assigns[name]
	if len(sites) == 0 {
		return nil
	}
	best := -1
	for i := range sites {
		if sites[i].line <= line && (best < 0 || sites[i].line >= sites[best].line) {
			best = i
		}
	}
	if best < 0 {
		return nil
	}
	return &sites[best]
}

// collectContractAssigns indexes every assignment_expression / init_declarator
// in the function body by its target variable name.
func collectContractAssigns(body parser.Node) map[string][]contractAssign {
	out := map[string][]contractAssign{}
	add := func(n parser.Node) {
		lhs, rhs, ok := n.AssignParts()
		if !ok {
			return
		}
		name := assignTargetName(lhs)
		if name == "" {
			return
		}
		out[name] = append(out[name], contractAssign{line: n.StartLine(), rhs: rhs})
	}
	for _, a := range body.FindAll("assignment_expression") {
		add(a)
	}
	for _, i := range body.FindAll("init_declarator") {
		add(i)
	}
	return out
}

// aliasOperand returns the value operand of a parenthesized/cast expression
// (skipping the type descriptor of a cast).
func aliasOperand(expr parser.Node) (parser.Node, bool) {
	for _, c := range expr.NamedChildren() {
		if c.Kind() == "type_descriptor" {
			continue
		}
		return c, true
	}
	return parser.Node{}, false
}

// voidPtrParamsOf returns the void*/const void* parameters of fn.
func voidPtrParamsOf(fn *db.Function, root parser.Node) map[string]bool {
	out := map[string]bool{}
	for _, def := range root.FindAll("function_definition") {
		if def.StartLine() != fn.StartLine {
			continue
		}
		for _, pd := range def.FindAll("parameter_declaration") {
			if !isVoidPointerDecl(pd) {
				continue
			}
			if n := declaratorName(pd); n != "" {
				out[n] = true
			}
		}
		break
	}
	return out
}

// isVoidPointerDecl reports whether a parameter_declaration is an opaque
// `void *` / `const void *` parameter (not a function-pointer parameter).
func isVoidPointerDecl(pd parser.Node) bool {
	hasVoid, hasPtr := false, false
	for _, c := range pd.NamedChildren() {
		switch c.Kind() {
		case "primitive_type", "type_identifier", "sized_type_specifier":
			if strings.TrimSpace(c.Text()) == "void" {
				hasVoid = true
			}
		case "pointer_declarator", "abstract_pointer_declarator":
			hasPtr = true
		case "function_declarator":
			return false
		}
	}
	return hasVoid && hasPtr
}

// bodyNullChecksVar reports whether the body null-checks v anywhere: a `v == NULL`
// / `v != NULL` comparison, a `!v` negation, or a bare `if (v)` / `while (v)`
// truth test. A function that inspects its parameter for NULL is NOT treating it
// as contract-guaranteed non-null, so it must not qualify as a contract param.
func bodyNullChecksVar(body parser.Node, v string) bool {
	for _, be := range body.FindAll("binary_expression") {
		if op := parser.BinaryOperator(be); op == "==" || op == "!=" {
			if parser.ExprNullChecksParam(be, v) {
				return true
			}
		}
	}
	for _, kind := range []string{"if_statement", "while_statement", "for_statement", "do_statement"} {
		for _, n := range body.FindAll(kind) {
			cond := n.ChildByFieldName("condition")
			if cond == nil {
				continue
			}
			if parser.ExprNullChecksParam(*cond, v) || parser.NullCheckedVariable(*cond) == v {
				return true
			}
			if strings.TrimSpace(cond.Text()) == v {
				return true
			}
		}
	}
	return false
}

// bodyReturnsVar reports whether the body returns v itself (`return v;`), which
// marks a passthrough wrapper whose purpose is to forward a possibly-null
// value, not a contract dereference.
func bodyReturnsVar(body parser.Node, v string) bool {
	for _, ret := range body.FindAll("return_statement") {
		kids := ret.NamedChildren()
		if len(kids) == 1 && kids[0].Kind() == "identifier" && kids[0].Text() == v {
			return true
		}
	}
	return false
}
