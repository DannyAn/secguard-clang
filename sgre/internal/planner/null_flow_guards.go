package planner

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// collectCountOutputFuncs returns, per in-scan function name, the set of
// PARAMETER INDICES whose pointed-to value the body zeroes (`*p = 0` /
// `*p = NULL`) AND whose body has a literal NULL return. That is the
// count-output contract: when such a function returns NULL it has already
// zeroed the pointed-to count, so a caller loop `for (i < n) arr[i]` over
// `arr = f(&n)` never dereferences a NULL arr (arr NULL forces n 0, the loop
// body never runs).
func collectCountOutputFuncs(cache *fileParseCache, funcs []*db.Function, fileByID map[int64]*db.File) map[string]map[int]bool {
	out := make(map[string]map[int]bool)
	for _, fn := range funcs {
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, _ := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		params := cache.paramsFor(file, fn)
		if len(params) == 0 {
			continue
		}
		zeroed := make(map[int]bool)
		for _, assign := range body.FindAll("assignment_expression") {
			lhs, rhs, ok := assign.AssignParts()
			if !ok {
				continue
			}
			param := derefParamName(lhs)
			if param == "" {
				continue
			}
			idx, isParam := params[param]
			if !isParam {
				continue
			}
			if parser.IsNullLiteral(rhs) {
				zeroed[idx] = true
			}
		}
		if len(zeroed) == 0 {
			continue
		}
		hasNullReturn := false
		for _, ret := range body.FindAll("return_statement") {
			children := ret.NamedChildren()
			if len(children) > 0 && parser.IsNullLiteral(children[0]) {
				hasNullReturn = true
				break
			}
		}
		if !hasNullReturn {
			continue
		}
		out[fn.Name] = zeroed
	}
	return out
}

// derefParamName returns the parameter name when expr is a pointer-dereference
// of a plain identifier (`*argc` → "argc"), else "".
func derefParamName(expr parser.Node) string {
	if expr.Kind() != "pointer_expression" {
		return ""
	}
	if strings.HasPrefix(strings.TrimSpace(expr.Text()), "&") {
		return ""
	}
	kids := expr.NamedChildren()
	if len(kids) != 1 || kids[0].Kind() != "identifier" {
		return ""
	}
	return kids[0].Text()
}

// addressOfVar returns the variable name when expr is `&x` (address-of a plain
// identifier), else "".
func addressOfVar(expr parser.Node) string {
	if expr.Kind() != "pointer_expression" {
		return ""
	}
	if !strings.HasPrefix(strings.TrimSpace(expr.Text()), "&") {
		return ""
	}
	kids := expr.NamedChildren()
	if len(kids) == 1 && kids[0].Kind() == "identifier" {
		return kids[0].Text()
	}
	return ""
}

// buildLoopBoundGuardMap records the subscript dereferences a loop bound
// guards: `arr = f(..., &n); for (i = 0; i < n; i++) arr[i]` dereferences arr
// only when n > 0, and f's count-output contract means arr == NULL forces
// n == 0 — so arr[i] is never a NULL deref.
func buildLoopBoundGuardMap(body parser.Node, countOutputFuncs map[string]map[int]bool) []ternaryGuardEntry {
	if body.Kind() != "compound_statement" || len(countOutputFuncs) == 0 {
		return nil
	}
	countPairs := make(map[string]string)
	forEachAssignment(body, func(lhs, rhs parser.Node) {
		arr := assignTargetName(lhs)
		if arr == "" {
			return
		}
		callee := rhsCallName(rhs)
		if callee == "" {
			return
		}
		zeroedIdx := countOutputFuncs[callee]
		if len(zeroedIdx) == 0 {
			return
		}
		for i, arg := range callArgs(rhs) {
			if v := addressOfVar(arg); v != "" && zeroedIdx[i] {
				countPairs[arr] = v
			}
		}
	})
	if len(countPairs) == 0 {
		return nil
	}
	var out []ternaryGuardEntry
	for _, forStmt := range body.FindAll("for_statement") {
		cond := forStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		induction, bound := loopInductionAndBound(*cond)
		if induction == "" || bound == "" {
			continue
		}
		loopBody := forStmt.ChildByFieldName("body")
		if loopBody == nil {
			continue
		}
		for _, se := range loopBody.FindAll("subscript_expression") {
			kids := se.NamedChildren()
			if len(kids) != 2 {
				continue
			}
			base := stripGuardCasts(kids[0])
			if base.Kind() != "identifier" || countPairs[base.Text()] != bound {
				continue
			}
			if strings.TrimSpace(kids[1].Text()) == induction {
				out = append(out, ternaryGuardEntry{variable: base.Text(), line: se.StartLine()})
			}
		}
	}
	return out
}

// loopInductionAndBound extracts the induction variable and upper bound of a
// plain `i < n` / `i <= n` / `i != n` loop condition, else ("", "").
func loopInductionAndBound(cond parser.Node) (string, string) {
	if cond.Kind() != "binary_expression" {
		return "", ""
	}
	switch parser.BinaryOperator(cond) {
	case "<", "<=", "!=":
	default:
		return "", ""
	}
	children := cond.NamedChildren()
	if len(children) != 2 {
		return "", ""
	}
	if children[0].Kind() != "identifier" || children[1].Kind() != "identifier" {
		return "", ""
	}
	return children[0].Text(), children[1].Text()
}

// stripGuardCasts unwraps cast and parenthesized expressions down to the
// operand (a local twin of evidence's stripCasts, kept in-package so the
// planner does not reach into evidence internals).
func stripGuardCasts(n parser.Node) parser.Node {
	for n.Kind() == "cast_expression" || n.Kind() == "parenthesized_expression" {
		next := parser.Node{}
		for _, c := range n.NamedChildren() {
			if c.Kind() == "type_descriptor" {
				continue
			}
			next = c
			break
		}
		if next.Kind() == "" {
			return n
		}
		n = next
	}
	return n
}

// derefGuardBaseChild returns the base operand of a field/subscript
// expression (the dereferenced pointer), or a zero Node.
func derefGuardBaseChild(n parser.Node) parser.Node {
	if n.Kind() != "field_expression" && n.Kind() != "subscript_expression" {
		return parser.Node{}
	}
	kids := n.NamedChildren()
	if len(kids) == 0 {
		return parser.Node{}
	}
	return kids[0]
}

// forEachAssignment visits every (lhs, rhs) pair of an assignment_expression or
// init_declarator inside a statement.
func forEachAssignment(stmt parser.Node, fn func(lhs, rhs parser.Node)) {
	for _, assign := range stmt.FindAll("assignment_expression") {
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		fn(children[0], children[1])
	}
	for _, init := range stmt.FindAll("init_declarator") {
		if lhs, rhs, ok := init.AssignParts(); ok {
			fn(lhs, rhs)
		}
	}
}

// assignTargetName returns the tracked variable name an assignment writes to,
// matching the evidence detectors' naming (field/subscript paths keep their full
// text). Writing through a dereference (`*p = ...`) returns "" because it does
// not change p itself.
func assignTargetName(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		return lhs.Text()
	case "field_expression", "subscript_expression":
		return lhs.Text()
	case "pointer_declarator", "array_declarator", "function_declarator":
		return declaratorName(lhs)
	}
	return ""
}

// declaratorName extracts the identifier a declarator names.
func declaratorName(n parser.Node) string {
	if n.Kind() == "identifier" {
		return n.Text()
	}
	for _, c := range n.NamedChildren() {
		if c.Kind() == "identifier" {
			return c.Text()
		}
		if name := declaratorName(c); name != "" {
			return name
		}
	}
	return ""
}

// rhsVarName returns the variable name when rhs is a bare identifier (possibly
// wrapped in parentheses or a cast), else "".
func rhsVarName(rhs parser.Node) string {
	switch rhs.Kind() {
	case "identifier":
		return rhs.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range rhs.NamedChildren() {
			if name := rhsVarName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

// fieldBaseName returns the base variable of a field/subscript location key
// (`p->f`, `p[i]`, `s.f`, `p->a->b`), or "" when the key is a bare variable or
// not a field/subscript path. It is the identifier before the first member or
// subscript access, so a chained path yields its top-level base. The base is
// trimmed so a spaced `p -> f` still resolves to the parameter name `p`.
func fieldBaseName(key string) string {
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '-':
			if i+1 < len(key) && key[i+1] == '>' {
				return strings.TrimSpace(key[:i])
			}
		case '.', '[':
			return strings.TrimSpace(key[:i])
		}
	}
	return ""
}

// copySourceKey returns the field-qualified location a value copies FROM, so
// `q = p->f` propagates the nullness of location p->f (not the whole p), and
// `q = a[i]` propagates location a[i]. It matches the detector's text-based
// keys (`p->f`, `p[i]`) so a NULL_VALUE source and a later copy/deref resolve to
// the same location. Bare `p` is the whole-variable location.
func copySourceKey(rhs parser.Node) string {
	switch rhs.Kind() {
	case "identifier", "field_expression", "subscript_expression":
		return rhs.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range rhs.NamedChildren() {
			if k := copySourceKey(c); k != "" {
				return k
			}
		}
	}
	return ""
}

// loadVarRefMaps resolves the variable_ref graph nodes for the analyzed
// functions: node ID -> variable name, line, and owning function. One bulk
// query per load pass (not one per function) keeps the three edge loaders from
// each re-implementing the same N+1 avoidance.
