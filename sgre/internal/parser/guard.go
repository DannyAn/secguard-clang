package parser

import "strings"

// BinaryOperator returns the operator token of a binary_expression node ("*",
// "/", "%", "+", "-", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "&", "|",
// "^", "<<", ">>"), or "" when there is none. The operator is an anonymous
// child, so it is read from Children() rather than NamedChildren().
func BinaryOperator(n Node) string {
	for _, c := range n.Children() {
		switch c.Kind() {
		case "*", "/", "%", "+", "-", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "&", "|", "^", "<<", ">>":
			return c.Kind()
		}
	}
	return ""
}

// IsNullOperand reports whether an operand of a comparison is a null pointer
// constant (NULL / nullptr / 0 / ((void*)0)). tree-sitter-c parses `NULL` as a
// `null` literal node, distinct from a plain identifier.
func IsNullOperand(op Node) bool {
	switch op.Kind() {
	case "null":
		return true
	case "identifier":
		return op.Text() == "nullptr"
	case "number_literal":
		return op.Text() == "0"
	case "parenthesized_expression", "cast_expression":
		for _, c := range op.NamedChildren() {
			if IsNullOperand(c) {
				return true
			}
		}
	}
	return false
}

// LvaluePath returns s when it is a plain C lvalue path — an identifier
// optionally followed by member (`->`, `.`) and subscript steps — and "" for
// anything else (a boolean combination, a call, a literal, a dereference). The
// text is returned unchanged, so it compares byte-for-byte with the name the
// dereference and null-source detectors derive from the same source text.
func LvaluePath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || !isCIdentStart(s[0]) {
		return ""
	}
	i := 0
	expectIdent := true
	for i < len(s) {
		if expectIdent {
			if !isCIdentStart(s[i]) {
				return ""
			}
			for i < len(s) && isCIdentPart(s[i]) {
				i++
			}
			expectIdent = false
			continue
		}
		switch {
		case strings.HasPrefix(s[i:], "->"):
			i += 2
			expectIdent = true
		case s[i] == '.':
			i++
			expectIdent = true
		case s[i] == '[':
			// The index expression is opaque here; it only has to be balanced.
			depth := 0
			for i < len(s) {
				switch s[i] {
				case '[':
					depth++
				case ']':
					depth--
				}
				i++
				if depth == 0 {
					break
				}
			}
			if depth != 0 {
				return ""
			}
		default:
			return ""
		}
	}
	if expectIdent {
		return "" // trailing `->` / `.`
	}
	return s
}

// GuardVarName normalises one operand of a null comparison: it trims
// parentheses and, for an assignment-in-condition (`(e = dictNext()) != NULL`),
// returns the assignment target `e` rather than the whole `e = dictNext()`.
func GuardVarName(operand string) string {
	t := strings.TrimSpace(operand)
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	// A lone leading/trailing parenthesis remains when the "=="/"!=" split cut a
	// parenthesized condition like `(p == NULL)` into `"(p "` + `" NULL)"`. Strip
	// it: a guard variable is a C identifier and never carries parentheses, so
	// this cannot over-trim a real name.
	t = strings.Trim(t, "()")
	if i := strings.Index(t, "="); i > 0 {
		t = strings.TrimSpace(t[:i])
	}
	t = strings.TrimPrefix(t, "*")
	return strings.TrimSpace(t)
}

// GuardedNonnullVars returns the variables a condition establishes as non-null
// when it evaluates TRUE. A `&&` conjunction guards every operand, a `||`
// disjunction guards none (at most one operand need be non-null), `p != NULL`
// guards p, and `p == NULL` / `!p` establish NULL rather than non-null and guard
// nothing. A branch-hint wrapper (`unlikely(p == NULL)`) is transparent: the
// wrapped condition is analysed instead.
func GuardedNonnullVars(cond Node) []string {
	switch cond.Kind() {
	case "parenthesized_expression", "cast_expression":
		for _, c := range cond.NamedChildren() {
			if vars := GuardedNonnullVars(c); len(vars) > 0 {
				return vars
			}
		}
		return nil
	}
	if inner, ok := UnwrapBranchHint(cond); ok {
		return GuardedNonnullVars(inner)
	}
	if cond.Kind() == "binary_expression" {
		switch BinaryOperator(cond) {
		case "&&":
			var vars []string
			for _, child := range cond.NamedChildren() {
				vars = append(vars, GuardedNonnullVars(child)...)
			}
			return vars
		case "||":
			return nil
		case "!=":
			if v := nonNullSideVar(cond); v != "" {
				return []string{v}
			}
		}
		return nil
	}
	if v := truthCheckedLvalue(cond); v != "" {
		return []string{v}
	}
	return nil
}

// NullCheckedVars returns the variables a condition establishes as non-null when
// it evaluates FALSE — the dual of GuardedNonnullVars. `p == NULL` false means p
// is non-null, so it guards p; `p != NULL` false means p is NULL and guards
// nothing; a `||` disjunction being false means every operand is false (so every
// operand's false-direction variable is guarded); a `&&` conjunction being false
// means at most one operand is false (nothing is guarded). A branch-hint wrapper
// (`unlikely(p == NULL)`) is transparent: the wrapped condition is analysed.
func NullCheckedVars(cond Node) []string {
	switch cond.Kind() {
	case "parenthesized_expression", "cast_expression":
		for _, c := range cond.NamedChildren() {
			if vars := NullCheckedVars(c); len(vars) > 0 {
				return vars
			}
		}
		return nil
	}
	if inner, ok := UnwrapBranchHint(cond); ok {
		return NullCheckedVars(inner)
	}
	if cond.Kind() == "binary_expression" {
		switch BinaryOperator(cond) {
		case "||":
			var vars []string
			for _, child := range cond.NamedChildren() {
				vars = append(vars, NullCheckedVars(child)...)
			}
			return vars
		case "&&":
			return nil
		case "==":
			if v := nonNullSideVar(cond); v != "" {
				return []string{v}
			}
		}
		return nil
	}
	if cond.Kind() == "unary_expression" {
		// `!p` false ⟹ p non-null.
		if v := unaryBareVar(cond); v != "" {
			return []string{v}
		}
	}
	return nil
}

// nonNullSideVar returns the non-null operand of a `==`/`!=` comparison
// (`p != NULL` → p, `NULL != p` → p, `(e = f()) != NULL` → e), or "".
func nonNullSideVar(cond Node) string {
	var nonNull string
	hasNull := false
	for _, c := range cond.NamedChildren() {
		if IsNullOperand(c) {
			hasNull = true
			continue
		}
		// Unwrap cast/paren structurally: `(struct T *)p != NULL` tests p, not
		// the garbage text `"struct T *)p"` a textual parenthesis trim produces.
		inner := c
		for inner.Kind() == "cast_expression" || inner.Kind() == "parenthesized_expression" {
			kids := inner.NamedChildren()
			var next Node
			for _, k := range kids {
				if k.Kind() == "type_descriptor" {
					continue
				}
				next = k
				break
			}
			if next.Kind() == "" {
				break
			}
			inner = next
		}
		if v := GuardVarName(strings.TrimSpace(inner.Text())); v != "" && v != "NULL" && v != "0" && nonNull == "" {
			nonNull = v
		}
	}
	if !hasNull {
		return ""
	}
	return nonNull
}

// truthCheckedLvalue returns the lvalue path a bare truth-check tests (`if (p)`,
// `if (arr[i])`, `if (p->f)`), or "" for a negation (`!p` — establishes NULL),
// a dereference (`*pp` — tests the pointee, not pp), or any non-lvalue.
func truthCheckedLvalue(cond Node) string {
	inner := cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			break
		}
		inner = kids[0]
	}
	if inner.Kind() == "unary_expression" {
		return ""
	}
	expr := strings.TrimSpace(inner.Text())
	if strings.HasPrefix(expr, "*") {
		return ""
	}
	return LvaluePath(expr)
}

// NullCheckedVariable returns the variable a null-check expression tests: the
// non-null operand of `p == NULL` / `NULL == p`, the operand of `!p`, or the bare
// lvalue itself (`p`). It is used where a guard re-derives the guarded variable
// from a caller-supplied null-check argument (guard macros, predicate helpers).
func NullCheckedVariable(cond Node) string {
	inner := cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			break
		}
		inner = kids[0]
	}
	switch inner.Kind() {
	case "binary_expression":
		if op := BinaryOperator(inner); op == "==" || op == "!=" {
			return nonNullSideVar(inner)
		}
	case "unary_expression":
		return unaryBareVar(inner)
	}
	return LvaluePath(strings.TrimSpace(inner.Text()))
}

// ExprNullChecksParam recognizes `param == NULL` / `NULL == param` / `!param`
// anywhere inside expr, recursing through parenthesized / cast / conditional /
// binary-|| containers. A field access (`param->f`) is structurally distinct
// from an identifier and so never matches, which is what excludes
// `param->content == NULL` from counting as a null-check of param itself.
func ExprNullChecksParam(expr Node, param string) bool {
	if expr.Kind() == "binary_expression" && BinaryOperator(expr) == "==" {
		var hasParam, hasNull bool
		for _, op := range expr.NamedChildren() {
			if op.Kind() == "identifier" && op.Text() == param {
				hasParam = true
			}
			if IsNullOperand(op) {
				hasNull = true
			}
		}
		return hasParam && hasNull
	}
	if expr.Kind() == "unary_expression" && strings.HasPrefix(strings.TrimSpace(expr.Text()), "!") {
		for _, op := range expr.NamedChildren() {
			if op.Kind() == "identifier" && op.Text() == param {
				return true
			}
		}
		return false
	}
	for _, c := range expr.NamedChildren() {
		if ExprNullChecksParam(c, param) {
			return true
		}
	}
	return false
}

// unaryBareVar returns the identifier operand of a unary_expression whose text
// is `!<ident>` (possibly parenthesized), or "".
func unaryBareVar(cond Node) string {
	inner := cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			break
		}
		inner = kids[0]
	}
	t := strings.TrimSpace(inner.Text())
	for strings.HasPrefix(t, "!") {
		t = strings.TrimSpace(t[1:])
	}
	t = strings.Trim(t, "()")
	if t == "" || t == "NULL" || t == "0" {
		return ""
	}
	return t
}

func isCIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isCIdentPart(c byte) bool {
	return isCIdentStart(c) || (c >= '0' && c <= '9')
}

// UnwrapBranchHint strips a branch-prediction hint wrapper from a condition:
// `unlikely(x)` / `likely(x)` / `__builtin_expect(x, n)` evaluate to exactly
// x, so the wrapped condition carries the guard semantics. Enterprise vendor
// macros are conventionally ALL-CAPS (`VOS_LIKELY`, `HRP_UNLIKELY`, `OS_LIKELY`)
// and are unwrapped by their `_LIKELY` / `_UNLIKELY` suffix — the CAPS suffix is
// required so a lowercase user checker (`check_likely`, `my_unlikely_handler`)
// is never unwrapped (that would treat its argument as the condition itself and
// manufacture a phantom guard). A lowercase vendor spelling stays fail-open:
// the guard is unrecognized and the candidate survives for the AI.
// `__builtin_expect`'s first argument is conventionally double-negated
// (`__builtin_expect(!!(x), 0)`), so paired `!!` negations are stripped too —
// an odd single `!` is left in place (stripping it would invert the guard's
// direction).
func UnwrapBranchHint(cond Node) (Node, bool) {
	if cond.Kind() != "call_expression" {
		return Node{}, false
	}
	kids := cond.NamedChildren()
	if len(kids) < 2 {
		return Node{}, false
	}
	name := strings.TrimSpace(kids[0].Text())
	switch name {
	case "likely", "unlikely", "__builtin_expect":
	default:
		if !strings.HasSuffix(name, "_LIKELY") && !strings.HasSuffix(name, "_UNLIKELY") {
			return Node{}, false
		}
	}

	args := kids[1].NamedChildren()
	if len(args) == 0 {
		return Node{}, false
	}
	inner := args[0]
	for inner.Kind() == "unary_expression" {
		ukids := inner.NamedChildren()
		if len(ukids) != 1 || ukids[0].Kind() != "unary_expression" || len(ukids[0].NamedChildren()) != 1 {
			break
		}
		inner = ukids[0].NamedChildren()[0]
	}
	return inner, true
}
