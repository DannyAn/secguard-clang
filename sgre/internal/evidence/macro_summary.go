package evidence

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// macroFreeSummary describes a function-like macro that frees (and optionally
// nulls) its first parameter: `#define SAFE_FREE(p) do { free(p); p = NULL; } while(0)`.
// tree-sitter exposes such macros as preproc_function_def nodes, whose body is a
// preproc_arg — the raw replacement text, analyzed here so a call to the macro
// can be treated as a free site.
type macroFreeSummary struct {
	freesArg bool
	nullsArg bool
}

// macroFreeSummaries returns, per macro name, whether its body frees the first
// parameter and whether it then nulls it. It is the macro layer the memory
// detectors consult so `#define my_free(p) free(p)` wrapping is not invisible.
func macroFreeSummaries(root parser.Node) map[string]macroFreeSummary {
	out := make(map[string]macroFreeSummary)
	for _, def := range root.FindAll("preproc_function_def") {
		name, param, body := "", "", ""
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_params":
				for _, p := range child.NamedChildren() {
					if p.Kind() == "identifier" && param == "" {
						param = p.Text()
					}
				}
			case "preproc_arg":
				body = child.Text()
			}
		}
		if name == "" || param == "" || body == "" {
			continue
		}
		s := macroFreeSummary{}
		if strings.Contains(body, "free("+param+")") || strings.Contains(body, "free ("+param+")") {
			s.freesArg = true
		}
		if s.freesArg && (strings.Contains(body, param+" = NULL") || strings.Contains(body, param+"=NULL") ||
			strings.Contains(body, param+" = 0")) {
			s.nullsArg = true
		}
		out[name] = s
	}
	return out
}

// macroWriteSummary describes a function-like macro that writes (initializes) its
// parameter: `#define GET(x) do { (x) = value; } while (0)`. tree-sitter exposes
// such macros as preproc_function_def nodes; a call to one passes its argument by
// NAME but the macro assigns to it, so the argument is an output, not a read of an
// uninitialized value.
type macroWriteSummary struct {
	writesArg bool
}

// macroWriteSummaries returns, per macro name, whether its body writes (assigns
// to, or takes the address of) its first parameter. It is the macro layer the
// uninit detector consults so `#define GET(x) (x) = ...` output macros are not
// mistaken for a by-value read of an uninitialized variable.
func macroWriteSummaries(root parser.Node) map[string]macroWriteSummary {
	out := make(map[string]macroWriteSummary)
	for _, def := range root.FindAll("preproc_function_def") {
		name, param, body := "", "", ""
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_params":
				for _, p := range child.NamedChildren() {
					if p.Kind() == "identifier" && param == "" {
						param = p.Text()
					}
				}
			case "preproc_arg":
				body = child.Text()
			}
		}
		if name == "" || param == "" || body == "" {
			continue
		}
		if macroAssignsParam(body, param) {
			out[name] = macroWriteSummary{writesArg: true}
		}
	}
	return out
}

// macroAssignsParam reports whether a function-like macro body PURELY writes its
// parameter — an address-of (`&x` / `&(x)`, passed to a writer) or an assignment
// whose RHS does not read the parameter back (`x = get()`, `(x) = v`). A
// read-modify-write (`x += v`, `x++`, `x = x + 1`) reads the uninitialized value
// first and is therefore a genuine defect, NOT an output — so it is not matched.
func macroAssignsParam(body, param string) bool {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, body)
	for _, p := range []string{param, "(" + param + ")"} {
		// Address-of never reads the value.
		if strings.Contains(compact, "&"+p) {
			return true
		}
		// `p = <rhs>` / `p=<rhs>` where <rhs> is independent of p (not a
		// read-modify-write) and the `=` is not a `==` comparison.
		idx := strings.Index(compact, p+"=")
		if idx < 0 {
			continue
		}
		after := compact[idx+len(p)+1:]
		if strings.HasPrefix(after, "=") {
			continue // `==`
		}
		inner := strings.Trim(p, "()")
		if strings.Contains(after, p) || strings.Contains(after, inner) {
			continue // read-modify-write
		}
		return true
	}
	return false
}
