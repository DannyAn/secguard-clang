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

// trustedMacros reports the set of function-like macros whose expansion computes
// a pointer from a memory address (field access + pointer arithmetic) rather than
// returning a possibly-null result (allocator / lookup). Third-party accessor
// macros such as DPDK's `rte_pktmbuf_mtod(m, t)` →
// `((t)((m)->buf_addr + (m)->data_off))` — possibly wrapped in another macro,
// e.g. `#define WRAPPER_MTOD(m, t) rte_pktmbuf_mtod(m, t)` — are trusted:
// callers dereference the result without a null check by contract, so a call to
// one must not seed a null source.
func trustedMacros(root parser.Node) map[string]bool {
	defs := make(map[string]string)
	for _, def := range root.FindAll("preproc_function_def") {
		name, body := "", ""
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_arg":
				body = child.Text()
			}
		}
		if name != "" && body != "" {
			defs[name] = body
		}
	}

	trusted := make(map[string]bool)
	visiting := make(map[string]bool)
	var isTrusted func(name string) bool
	isTrusted = func(name string) bool {
		if trusted[name] {
			return true
		}
		body, ok := defs[name]
		if !ok || visiting[name] {
			return false
		}
		visiting[name] = true
		defer delete(visiting, name)

		// Field access + pointer arithmetic: computes an address inside an
		// object (e.g. buf_addr + data_off), not a possibly-null allocation.
		if strings.Contains(body, "->") && strings.Contains(body, "+") {
			trusted[name] = true
			return true
		}
		// Nested macro wrapper: trusted if it expands to a trusted macro.
		for other := range defs {
			if other != name && strings.Contains(body, other) && isTrusted(other) {
				trusted[name] = true
				return true
			}
		}
		return false
	}
	for name := range defs {
		isTrusted(name)
	}
	return trusted
}
