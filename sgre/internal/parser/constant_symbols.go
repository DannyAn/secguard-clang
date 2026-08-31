package parser

import (
	"strconv"
	"strings"
)

// ConstantEnv is the per-file set of compile-time integer constants whose value
// is provably non-zero: object-like macros, enumerators with an explicit value,
// and top-level const variables. Consumers (the divide-by-zero detector and the
// planner's cross-function return-summary) use it so a name spelled as a macro
// (`#define BKT_NUM 4096`) in a divisor or return value is treated like the
// literal `4096` instead of a "possibly-zero variable". Only symbols with a
// determinable non-zero value are recorded; anything undeterminable is left
// absent so it keeps flowing exactly as before — a real divide-by-zero must never
// be suppressed by an over-eager table.
type ConstantEnv struct {
	nonZero map[string]bool
}

func NewConstantEnv() *ConstantEnv {
	return &ConstantEnv{nonZero: make(map[string]bool)}
}

// NonZero reports whether name is a compile-time constant known to be non-zero.
func (e *ConstantEnv) NonZero(name string) bool {
	return e.nonZero[strings.TrimSpace(name)]
}

// CollectConstantSymbols scans a translation unit for compile-time integer
// constants with a non-zero value: object-like macros (`#define X 20`),
// enumerators with an explicit literal (`enum { MAX = 4096 }`), and top-level
// `const` integer variables (`const int N = 8`). Function-like macros, macro
// bodies that are not a simple constant, implicit enumerators, and pointer
// declarations are deliberately skipped because their value cannot be determined
// here.
func CollectConstantSymbols(root Node) *ConstantEnv {
	env := NewConstantEnv()

	for _, def := range root.FindAll("preproc_def") {
		name, value := "", ""
		functionLike := false
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_params":
				functionLike = true
			case "preproc_arg":
				value = child.Text()
			}
		}
		if name == "" || functionLike || value == "" {
			continue
		}
		if NonZeroConstantValue(value) {
			env.nonZero[name] = true
		}
	}

	for _, en := range root.FindAll("enumerator") {
		name, value := "", ""
		for _, child := range en.NamedChildren() {
			if child.Kind() == "identifier" && name == "" {
				name = child.Text()
			}
		}
		if name == "" {
			continue
		}
		if idx := strings.Index(en.Text(), "="); idx >= 0 {
			value = strings.TrimSpace(en.Text()[idx+1:])
		}
		if value == "" {
			continue
		}
		if NonZeroConstantValue(value) {
			env.nonZero[name] = true
		}
	}

	for _, decl := range root.NamedChildren() {
		if decl.Kind() != "declaration" || !declIsConst(decl) {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			name, value := "", ""
			for _, c := range child.NamedChildren() {
				switch c.Kind() {
				case "identifier":
					name = c.Text()
				case "number_literal":
					value = c.Text()
				}
			}
			if name == "" || value == "" {
				continue
			}
			if NonZeroConstantValue(value) {
				env.nonZero[name] = true
			}
		}
	}

	return env
}

// declIsConst reports whether a top-level declaration declares a const
// non-pointer object (`const int N = 8`). A `const int *p` declaration qualifies
// the pointed-to object, not the pointer itself, so it is excluded.
func declIsConst(decl Node) bool {
	text := decl.Text()
	return strings.Contains(text, "const") && !strings.Contains(text, "*")
}

// NonZeroConstantValue reports whether a constant-expression text is provably a
// non-zero integer value: a non-zero integer literal (decimal/hex/octal, with C
// suffixes and an optional sign), a sizeof (compile-time constant, always > 0),
// or a parenthesized form of either. Complex expressions (`(1u << 3)`) and
// non-integer literals are not resolved and return false, so the caller keeps the
// conservative "possibly zero" verdict rather than risk a false negative.
func NonZeroConstantValue(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "sizeof") {
		return true
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
		return false
	}
	v, err := strconv.ParseInt(t, 0, 64)
	if err != nil {
		return false
	}
	if neg {
		v = -v
	}
	return v != 0
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
