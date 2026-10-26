package parser

import "strings"

// CollectMacroValues resolves object-like `#define NAME 10` macros to their
// numeric value, so an array sized by a macro (`int arr[MAX]`) is not silently
// treated as unknown-size. Function-like macros are ignored.
func CollectMacroValues(root Node) map[string]int {
	macros := make(map[string]int)
	for _, def := range root.FindAll("preproc_def") {
		var name string
		value := -1
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "number_literal":
				if v := parseIntLiteral(child.Text()); v >= 0 {
					value = v
				}
			case "preproc_arg":
				if v := parseIntLiteral(strings.TrimSpace(child.Text())); v >= 0 {
					value = v
				}
			}
		}
		if name != "" && value >= 0 {
			macros[name] = value
		}
	}
	return macros
}

// parseIntLiteral parses a decimal/hex C integer literal, returning -1 when the
// text is not a plain literal (a suffixed or expression-bodied macro stays
// unresolved rather than guessed).
func parseIntLiteral(text string) int {
	t := strings.TrimSpace(text)
	t = strings.TrimRight(t, "uUlL")
	if t == "" {
		return -1
	}
	base := 10
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		base = 16
		t = t[2:]
	} else if len(t) > 1 && t[0] == '0' {
		base = 8
		t = t[1:]
	}
	if base == 16 {
		v := 0
		for _, r := range t {
			var d int
			switch {
			case r >= '0' && r <= '9':
				d = int(r - '0')
			case r >= 'a' && r <= 'f':
				d = int(r-'a') + 10
			case r >= 'A' && r <= 'F':
				d = int(r-'A') + 10
			default:
				return -1
			}
			v = v*16 + d
		}
		return v
	}
	v := 0
	for _, r := range t {
		if r < '0' || r > '9' {
			return -1
		}
		v = v*base + int(r-'0')
	}
	return v
}

// CollectStringMacros reports object-like macros whose expansion is a C string
// literal (`#define MSG_FMT "%d"`, `#define HELLO L"hi"`, adjacent literals
// included). A call-site argument spelled with one of these names is a
// COMPILE-TIME CONSTANT, so the format/path call-site census must count it as
// literal, not as a variable: two callers passing `MSG_FMT` were counted
// `2-var`, the all-literal gate never fired, and a wrapper whose every caller
// passes a constant format was reported as a format-string defect.
// Function-like macros are ignored (their expansion may depend on the argument).
func CollectStringMacros(root Node) map[string]bool {
	out := map[string]bool{}
	for _, def := range root.FindAll("preproc_def") {
		name, body := "", ""
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_arg":
				body = strings.TrimSpace(child.Text())
			}
		}
		if name == "" || body == "" {
			continue
		}
		if isCStringLiteralText(body) {
			out[name] = true
		}
	}
	return out
}

// isCStringLiteralText reports whether s is one or more concatenated C string
// literals (with an optional L/u8/u/U prefix). Anything else — an expression, a
// function call, a bare identifier — is not a compile-time string constant.
func isCStringLiteralText(s string) bool {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{"u8", "u", "U", "L"} {
		if strings.HasPrefix(s, prefix) {
			s = strings.TrimSpace(s[len(prefix):])
			break
		}
	}
	for s != "" {
		if strings.HasPrefix(s, "/*") || strings.HasPrefix(s, "//") {
			return true
		}
		if !strings.HasPrefix(s, `"`) {
			return false
		}
		i := 1
		closed := false
		for i < len(s) {
			switch s[i] {
			case '\\':
				i += 2
				continue
			case '"':
				i++
				closed = true
			}
			if closed {
				break
			}
			i++
		}
		if !closed {
			return false
		}
		s = strings.TrimSpace(s[i:])
	}
	return true
}
