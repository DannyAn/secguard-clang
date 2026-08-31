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

// macroWriteSummary describes a function-like macro that writes (initializes) one
// or more of its parameters: `#define GET(x) do { (x) = value; } while (0)`.
// tree-sitter exposes such macros as preproc_function_def nodes; a call to one
// passes its argument by NAME but the macro assigns to it, so the argument is an
// output, not a read of an uninitialized value. writesParam[i] is true when the
// i-th parameter is written.
type macroWriteSummary struct {
	writesParam map[int]bool
}

// macroWriteSummaries returns, per macro name, which parameter positions its body
// writes (assigns to, or takes the address of). It is the macro layer the uninit
// detector consults so `#define GET(x) (x) = ...` output macros are not mistaken
// for a by-value read of an uninitialized variable — including multi-parameter
// macros such as `RW_POOL_FOR(group_id, pool_id)`, whose SECOND parameter is the
// loop variable the macro initializes.
func macroWriteSummaries(root parser.Node) map[string]macroWriteSummary {
	out := make(map[string]macroWriteSummary)
	for _, def := range root.FindAll("preproc_function_def") {
		name, body := "", ""
		var params []string
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "preproc_params":
				for _, p := range child.NamedChildren() {
					if p.Kind() == "identifier" {
						params = append(params, p.Text())
					}
				}
			case "preproc_arg":
				body = child.Text()
			}
		}
		if name == "" || body == "" {
			continue
		}
		summary := macroWriteSummary{writesParam: make(map[int]bool)}
		for i, param := range params {
			if macroAssignsParam(body, param) {
				summary.writesParam[i] = true
			}
		}
		if len(summary.writesParam) > 0 {
			out[name] = summary
		}
	}
	return out
}

// isIdentChar reports whether c can appear within a C identifier.
func isIdentChar(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// identTokenIndexes returns the byte offsets in s where name occurs as a
// standalone C identifier (neither preceded nor followed by an identifier
// character), so a single-character parameter (`c`) is not matched inside a
// longer identifier (`combine`).
func identTokenIndexes(s, name string) []int {
	var idxs []int
	for i := 0; i+len(name) <= len(s); i++ {
		if s[i:i+len(name)] != name {
			continue
		}
		if i > 0 && isIdentChar(s[i-1]) {
			continue
		}
		if j := i + len(name); j < len(s) && isIdentChar(s[j]) {
			continue
		}
		idxs = append(idxs, i)
		i += len(name) - 1
	}
	return idxs
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

	// Bare spelling: match only as a standalone identifier.
	for _, i := range identTokenIndexes(compact, param) {
		// `&p` (address-of) is a write target; exclude `&&p` (logical AND).
		if i > 0 && compact[i-1] == '&' && (i < 2 || compact[i-2] != '&') {
			return true
		}
		// `p = <rhs>` is an assignment LHS; exclude `==`.
		j := i + len(param)
		if j >= len(compact) || compact[j] != '=' || (j+1 < len(compact) && compact[j+1] == '=') {
			continue
		}
		if !rhsReadsParam(compact[j+1:], param) {
			return true
		}
	}

	// Parenthesized spelling `(p)` — the parens delimit the token, so a plain
	// substring match is safe even for single-character names.
	p := "(" + param + ")"
	if strings.Contains(compact, "&"+p) {
		return true
	}
	if i := strings.Index(compact, p+"="); i >= 0 {
		after := compact[i+len(p)+1:]
		if !strings.HasPrefix(after, "=") && !rhsReadsParam(after, param) {
			return true
		}
	}
	return false
}

// rhsReadsParam reports whether an assignment RHS reads param back, delimiting the
// RHS at the end of the assignment's expression (`;`, `)`, or `}`). A LATER use
// of the parameter in a subsequent expression — e.g. the condition/update that
// follow a for-init write in `for ((p) = f(); p != END; (p) = next((p)))` — must
// not make an initializing write look like a read-modify-write.
func rhsReadsParam(rhs, param string) bool {
	if i := strings.IndexAny(rhs, ");}"); i >= 0 {
		rhs = rhs[:i]
	}
	return len(identTokenIndexes(rhs, param)) > 0 || strings.Contains(rhs, "("+param+")")
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
