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
