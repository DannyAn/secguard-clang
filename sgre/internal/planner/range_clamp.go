package planner

import "github.com/DannyAn/secguard-clang/internal/parser"

// range_clamp.go recognizes the zero-clamp idiom that voids a caller-side
// literal-zero proof (issue #253 P2-1): `if (p == 0) { p = DEFAULT; }` means a
// caller passing 0 does NOT reach a division with a zero divisor, so the
// param-zero auto-confirm must not fire.

// paramZeroClamp reports whether the function body assigns the parameter a
// replacement value inside an `if (param == 0)` branch. Any assignment in that
// branch voids the "caller passed 0 ⇒ divisor is 0" proof; the AI judges the
// replacement value instead of the engine auto-confirming.
func paramZeroClamp(body parser.Node, param string) bool {
	if body.Kind() == "" || param == "" {
		return false
	}
	for _, ifs := range body.FindAll("if_statement") {
		cond := ifs.ChildByFieldName("condition")
		if cond == nil || !isZeroEqualityCheck(*cond, param) {
			continue
		}
		for _, assign := range ifs.FindAll("assignment_expression") {
			children := assign.NamedChildren()
			if len(children) < 2 {
				continue
			}
			if name, ok := guardIdent(children[0]); ok && name == param {
				return true
			}
		}
	}
	return false
}

// isZeroEqualityCheck matches `param == 0` and the mirrored `0 == param`.
func isZeroEqualityCheck(cond parser.Node, param string) bool {
	for cond.Kind() == "parenthesized_expression" {
		ch := cond.NamedChildren()
		if len(ch) == 0 {
			return false
		}
		cond = ch[0]
	}
	if cond.Kind() != "binary_expression" || binaryOperatorToken(cond) != "==" {
		return false
	}
	children := cond.NamedChildren()
	if len(children) != 2 {
		return false
	}
	for _, ij := range [][2]int{{0, 1}, {1, 0}} {
		if name, ok := guardIdent(children[ij[0]]); ok && name == param {
			if v, ok := foldConstExpr(children[ij[1]]); ok && v == 0 {
				return true
			}
		}
	}
	return false
}
