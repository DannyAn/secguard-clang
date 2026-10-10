package parser

import (
	"strconv"
	"strings"
)

// ConstantEnv is the per-file set of compile-time integer constants: object-like
// macros, enumerators with an explicit value, and top-level const variables.
// Consumers (the divide-by-zero detector) use it so a name spelled as a macro
// (`#define BKT_NUM 4096`) in a divisor is treated like the literal `4096`
// instead of a "possibly-zero variable". Only symbols with a determinable value
// are recorded; anything undeterminable is left absent so a real divide-by-zero
// must never be suppressed by an over-eager table.
type ConstantEnv struct {
	nonZero map[string]bool
	zero    map[string]bool
}

func NewConstantEnv() *ConstantEnv {
	return &ConstantEnv{nonZero: make(map[string]bool), zero: make(map[string]bool)}
}

// NonZero reports whether name is a compile-time constant known to be non-zero.
func (e *ConstantEnv) NonZero(name string) bool {
	return e.nonZero[strings.TrimSpace(name)]
}

// IsZero reports whether name is a compile-time constant known to be exactly
// zero (`#define ZERO 0`), so `x / ZERO` is a certain divide-by-zero.
func (e *ConstantEnv) IsZero(name string) bool {
	return e.zero[strings.TrimSpace(name)]
}

// NonZeroExpr reports whether expr is a provably non-zero compile-time integer
// constant expression, resolving identifier leaves against this environment so
// a divisor spelled `HOURS * MINS * SECS` folds like `24 * 60 * 60` when each
// symbol is a known non-zero constant. It is the expression-level counterpart
// to NonZero (which matches one bare name). It stays conservative: only
// operators that cannot turn non-zero operands into zero are folded (`*`, `<<`,
// unary `+`/`-`, sizeof, parentheses); anything else returns false.
func (e *ConstantEnv) NonZeroExpr(expr string) bool {
	return foldNonZeroConstant(expr, e)
}

// Merge merges other into e. A symbol that is nonZero in one env and zero in
// another is a conflict (the symbol has different values in different
// translation units) and is dropped from both maps so neither NonZero nor
// IsZero will report it — the conservative outcome for an undeterminable name.
func (e *ConstantEnv) Merge(other *ConstantEnv) {
	if other == nil {
		return
	}
	for name := range other.nonZero {
		if e.zero[name] {
			delete(e.nonZero, name)
			delete(e.zero, name)
			continue
		}
		e.nonZero[name] = true
	}
	for name := range other.zero {
		if e.nonZero[name] {
			delete(e.nonZero, name)
			delete(e.zero, name)
			continue
		}
		e.zero[name] = true
	}
}

// CollectConstantSymbols scans a translation unit for compile-time integer
// constants with a determinable value: object-like AND constant-bodied
// function-like macros (`#define X 20`, `#define WORKERS() 8`), enumerators
// (explicit or implicit), and `const` integer variables at any scope. Only
// symbols with a determinable value are recorded; anything undeterminable is
// left absent so a real divide-by-zero must never be suppressed by an
// over-eager table.
func CollectConstantSymbols(root Node) *ConstantEnv {
	env := NewConstantEnv()

	for _, def := range root.FindAll("preproc_def") {
		name, value := "", ""
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_arg":
				value = child.Text()
			}
		}
		if name == "" || value == "" {
			continue
		}
		if NonZeroConstantValue(value) {
			env.nonZero[name] = true
		} else if IsZeroConstantValue(value) {
			env.zero[name] = true
		}
	}
	// A function-like macro with a simple constant body (`#define WORKERS() 8`)
	// is still a compile-time constant; record the call spelling so a divisor
	// `WORKERS()` resolves. A non-constant body is skipped.
	for _, def := range root.FindAll("preproc_function_def") {
		name, value := "", ""
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_arg":
				value = child.Text()
			}
		}
		if name == "" || value == "" || (!NonZeroConstantValue(value) && !IsZeroConstantValue(value)) {
			continue
		}
		if NonZeroConstantValue(value) {
			env.nonZero[name+"()"] = true
		} else {
			env.zero[name+"()"] = true
		}
	}

	// Enumerators carry an implicit running value when no `=` is present:
	// `enum { A, B, C = 5, D }` → A=0, B=1, C=5, D=6.
	running := int64(0)
	runningValid := true
	for _, en := range root.FindAll("enumerator") {
		name := ""
		for _, child := range en.NamedChildren() {
			if child.Kind() == "identifier" && name == "" {
				name = child.Text()
			}
		}
		if name == "" {
			continue
		}
		var v int64
		if idx := strings.Index(en.Text(), "="); idx >= 0 {
			pv, ok := parseConstantInt(strings.TrimSpace(en.Text()[idx+1:]))
			if !ok {
				runningValid = false
				continue // undeterminable explicit value: stop tracking the run
			}
			v = pv
		} else {
			if !runningValid {
				continue
			}
			v = running
		}
		if v == 0 {
			env.zero[name] = true
		} else {
			env.nonZero[name] = true
		}
		running = v + 1
		runningValid = true
	}

	for _, decl := range root.FindAll("declaration") {
		if !strings.Contains(decl.Text(), "const") {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			// Skip a pointer declarator (`const int *p` / `const int x = 8, *p`):
			// the const qualifies the pointed-to object, not the pointer value.
			if strings.Contains(child.Text(), "*") {
				continue
			}
			name, value := "", ""
			for _, c := range child.NamedChildren() {
				switch c.Kind() {
				case "identifier":
					if name == "" {
						name = c.Text()
					}
				case "number_literal", "parenthesized_expression":
					if value == "" {
						value = c.Text()
					}
				}
			}
			if name == "" || value == "" {
				continue
			}
			if NonZeroConstantValue(value) {
				env.nonZero[name] = true
			} else if IsZeroConstantValue(value) {
				env.zero[name] = true
			}
		}
	}

	return env
}

// NonZeroConstantValue reports whether a constant-expression text is provably a
// non-zero integer value: a non-zero integer literal (decimal/hex/octal, with C
// suffixes and an optional sign), a sizeof (compile-time constant, always > 0),
// or a parenthesized form of either. It also folds a conservative subset of
// composite constant expressions (see foldNonZeroConstant) so a macro body like
// `(24 * 60 * 60)` resolves non-zero exactly like the literal `86400`. Anything
// that cannot be proven non-zero — a non-integer literal, an operator that can
// yield zero from non-zero operands (`+ - / % >> & | ^`), or an unknown leaf —
// returns false, so the caller keeps the conservative "possibly zero" verdict
// rather than risk a false negative.
func NonZeroConstantValue(text string) bool {
	if v, ok := parseConstantInt(text); ok {
		return v != 0
	}
	return foldNonZeroConstant(text, nil)
}

// IsZeroConstantValue reports whether a constant-expression text is provably a
// zero integer literal (`0`, `0x0`, `00`, with C suffixes and an optional sign).
// It is the exact complement needed to auto-confirm `x / 0` as a certain
// divide-by-zero rather than a "possibly-zero" suspected lead.
func IsZeroConstantValue(text string) bool {
	if strings.HasPrefix(strings.TrimSpace(text), "sizeof") {
		return false
	}
	v, ok := parseConstantInt(text)
	return ok && v == 0
}

// parseConstantInt parses a C integer literal (with optional sign and u/U/l/L
// suffixes, possibly parenthesized) into its value. It returns ok=false for
// anything it cannot resolve (a non-numeric name, a complex expression).
func parseConstantInt(text string) (int64, bool) {
	t := strings.TrimSpace(text)
	if t == "" {
		return 0, false
	}
	t = stripParens(t)
	t = strings.TrimSpace(t)

	neg := false
	if strings.HasPrefix(t, "-") {
		neg = true
		t = strings.TrimSpace(t[1:])
	} else if strings.HasPrefix(t, "+") {
		t = strings.TrimSpace(t[1:])
	}
	t = strings.TrimRight(t, "uUlL")
	if t == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(t, 0, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		v = -v
	}
	return v, true
}

// stripParens removes one or more outer layers of surrounding parentheses from a
// condition text so `(20)` matches the same numeric literal as `20`.
func stripParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		inner := s[1 : len(s)-1]
		if balanced(inner) {
			s = strings.TrimSpace(inner)
		} else {
			break
		}
	}
	return s
}

func balanced(s string) bool {
	depth := 0
	for _, c := range s {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// foldNonZeroConstant reports whether text is provably a non-zero integer
// constant expression. It folds a conservative subset of C integer constant
// expressions where non-zero inputs are GUARANTEED to stay non-zero:
//   - a non-zero integer literal / sizeof / known non-zero symbol (leaf)
//   - multiplication: nz * nz is nz (integer multiplication never zeroes two
//     non-zero operands in source-level arithmetic)
//   - left shift: nz << any is nz (a non-zero value shifted stays non-zero)
//   - unary +/-, and parenthesized forms recurse
//
// Every other operator (`+ - / % >> & | ^`) is deliberately NOT folded: `a - b`
// or `a / b` can be zero even when both operands are non-zero (e.g. `1 / 2`),
// so folding it would risk suppressing a genuine divide-by-zero. Any unknown
// leaf (a parameter, a field, a call, a non-integer literal) also returns false.
func foldNonZeroConstant(text string, env *ConstantEnv) bool {
	t := strings.TrimSpace(text)
	if t == "" {
		return false
	}
	if t[0] == '+' || t[0] == '-' {
		return foldNonZeroConstant(t[1:], env)
	}
	t = strings.TrimSpace(stripParens(t))
	if t == "" {
		return false
	}
	left, op, right, found := topLevelBinaryOp(t)
	if !found {
		if strings.HasPrefix(strings.TrimSpace(t), "sizeof") {
			return true
		}
		if v, ok := parseConstantInt(t); ok {
			return v != 0
		}
		if env != nil && env.NonZero(t) {
			return true
		}
		return false
	}
	switch op {
	case "*":
		return foldNonZeroConstant(left, env) && foldNonZeroConstant(right, env)
	case "<<":
		return foldNonZeroConstant(left, env)
	default:
		return false
	}
}

// topLevelBinaryOp splits text at the parenthesization-depth-0 binary operator of
// lowest precedence, returning that operator and its left/right operands, or
// found=false when text has no top-level operator. Precedence follows C
// (multiplicative 40 > additive 30 > shift 20); the lowest-precedence operator is
// the split point so a `+`/`-` outermost operator is rejected even when its `*`
// sub-expressions are individually non-zero. A lone `-`/`+` in front of an
// operand is a unary sign, handled by foldNonZeroConstant before scanning.
func topLevelBinaryOp(t string) (left, op, right string, found bool) {
	depth := 0
	minPrio := 1 << 30
	bestIdx := -1
	bestOp := ""
	bestLen := 0
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case '(':
			depth++
			continue
		case ')':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		var opTok string
		var prio int
		switch t[i] {
		case '*', '/', '%':
			opTok, prio = string(t[i]), 40
		case '+', '-':
			opTok, prio = string(t[i]), 30
		case '<':
			if i+1 < len(t) && t[i+1] == '<' {
				opTok, prio = "<<", 20
			}
		case '>':
			if i+1 < len(t) && t[i+1] == '>' {
				opTok, prio = ">>", 20
			}
		}
		if opTok == "" {
			continue
		}
		if prio < minPrio {
			minPrio = prio
			bestIdx = i
			bestOp = opTok
			bestLen = len(opTok)
		}
		if len(opTok) == 2 {
			i++
		}
	}
	if bestIdx < 0 {
		return "", "", "", false
	}
	left = strings.TrimSpace(t[:bestIdx])
	right = strings.TrimSpace(t[bestIdx+bestLen:])
	if left == "" || right == "" {
		return "", "", "", false
	}
	return left, bestOp, right, true
}
