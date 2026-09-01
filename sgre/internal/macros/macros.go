// Package macros analyzes function-like macro definitions to determine which of
// a macro's parameters it writes through (output parameters). It is the macro
// layer shared by the uninit detector and the planner's definite-init filter so
// that a macro output argument (`#define OUT(x) (x) = ...` → `OUT(v)`) is a
// write, not a read of an uninitialized value.
package macros

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// WriteSummary describes a function-like macro that writes (initializes) one or
// more of its parameters: `#define GET(x) do { (x) = value; } while (0)`.
// tree-sitter exposes such macros as preproc_function_def nodes; a call to one
// passes its argument by NAME but the macro assigns to it, so the argument is an
// output, not a read of an uninitialized value. writesParam[i] is true when the
// i-th parameter is written.
type WriteSummary struct {
	writesParam map[int]bool
}

// WriteSummaries returns, per macro name, which parameter positions its body
// writes (assigns to, or takes the address of). It recognizes multi-parameter
// macros whose SECOND (or any other) parameter is the loop variable / output the
// macro initializes.
func WriteSummaries(root parser.Node) map[string]WriteSummary {
	out := make(map[string]WriteSummary)
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
		summary := WriteSummary{writesParam: make(map[int]bool)}
		for i, param := range params {
			if assignsParam(body, param) {
				summary.writesParam[i] = true
			}
		}
		if len(summary.writesParam) > 0 {
			out[name] = summary
		}
	}
	return out
}

// WrittenArgs returns the set of bare-identifier arguments passed to a macro at
// a parameter position the macro writes. Such an argument is an output the macro
// initializes, not a read of an uninitialized value. Only the argument positions
// whose corresponding parameter is written are returned; the other arguments are
// still reads.
func WrittenArgs(call parser.Node, summaries map[string]WriteSummary) map[string]bool {
	out := make(map[string]bool)
	summary, ok := summaries[callName(call)]
	if !ok || len(summary.writesParam) == 0 {
		return out
	}
	for _, child := range call.NamedChildren() {
		if child.Kind() != "argument_list" {
			continue
		}
		args := child.NamedChildren()
		for i, arg := range args {
			if !summary.writesParam[i] {
				continue
			}
			if arg.Kind() == "identifier" {
				out[arg.Text()] = true
			}
		}
	}
	return out
}

// MergeWriteSummaries combines per-file write-summary maps into one. A macro
// defined in one file (typically a .h header) and called in another (.c source)
// is invisible to the per-file WriteSummaries of the source file; merging across
// the whole scan tree makes the macro's written-argument signature available at
// every call site. When the same macro name is defined in multiple files, the
// written parameter positions are unioned (a macro is an output at a position if
// ANY of its definitions writes that position).
func MergeWriteSummaries(maps ...map[string]WriteSummary) map[string]WriteSummary {
	out := make(map[string]WriteSummary)
	for _, m := range maps {
		for name, s := range m {
			if existing, ok := out[name]; ok {
				for i := range s.writesParam {
					existing.writesParam[i] = true
				}
				out[name] = existing
				continue
			}
			cp := WriteSummary{writesParam: make(map[int]bool, len(s.writesParam))}
			for i := range s.writesParam {
				cp.writesParam[i] = true
			}
			out[name] = cp
		}
	}
	return out
}

// callName returns the callee identifier of a call_expression node.
func callName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
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

// assignsParam reports whether a function-like macro body PURELY writes its
// parameter — an address-of (`&x` / `&(x)`, passed to a writer) or an assignment
// whose RHS does not read the parameter back (`x = get()`, `(x) = v`). A
// read-modify-write (`x += v`, `x++`, `x = x + 1`) reads the uninitialized value
// first and is therefore a genuine defect, NOT an output — so it is not matched.
func assignsParam(body, param string) bool {
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

// GuardSummary describes a function-like macro that returns early when one of its
// parameters indicates a null pointer (a guard macro):
// `#define CHECK_RET(cond, ret) if ((cond)) { return ret; }`.
//
//   - guardsParam[i] is true when the macro's `if (param) return` guards the i-th
//     parameter: the caller passes a null-check EXPRESSION (`var == NULL`, `!var`).
//   - guardsParamNegated[i] is true when `if (!param) return` guards it: the
//     caller passes the VARIABLE itself (`var`).
type GuardSummary struct {
	guardsParam        map[int]bool
	guardsParamNegated map[int]bool
}

// GuardSummaries returns, per macro name, which parameter positions its body
// guards with an early return (`if (<cond>) return ...`).
func GuardSummaries(root parser.Node) map[string]GuardSummary {
	out := make(map[string]GuardSummary)
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
		plain, negated := guardParamsInBody(body, params)
		if len(plain) == 0 && len(negated) == 0 {
			continue
		}
		out[name] = GuardSummary{guardsParam: plain, guardsParamNegated: negated}
	}
	return out
}

// GuardedArgs returns the argument indices a macro call guards, keyed by index
// with the value reporting whether the guard negates the parameter (true for
// `if (!param) return`, false for `if (param) return`).
func GuardedArgs(call parser.Node, summaries map[string]GuardSummary) map[int]bool {
	summary, ok := summaries[callName(call)]
	if !ok {
		return nil
	}
	out := make(map[int]bool)
	for i := range summary.guardsParam {
		out[i] = false
	}
	for i := range summary.guardsParamNegated {
		out[i] = true
	}
	return out
}

// guardParamsInBody reports, for a macro body, which parameters are referenced by
// the `if` condition of an early-return guard (`if (<cond>) return`), split into
// negated (`!p` / `!(p)`) and non-negated (`p`) spellings.
func guardParamsInBody(body string, params []string) (plain, negated map[int]bool) {
	plain, negated = make(map[int]bool), make(map[int]bool)
	compact := compactBody(body)
	ifIdx := strings.Index(compact, "if(")
	if ifIdx < 0 {
		return plain, negated
	}
	close := matchingParen(compact, ifIdx+2)
	if close < 0 || !strings.Contains(compact[close+1:], "return") {
		return plain, negated
	}
	cond := compact[ifIdx+3 : close]
	for i, p := range params {
		for _, pos := range identTokenIndexes(cond, p) {
			if pos >= 2 && cond[pos-2] == '!' && cond[pos-1] == '(' {
				negated[i] = true
				continue
			}
			if pos >= 1 && cond[pos-1] == '!' {
				negated[i] = true
				continue
			}
			plain[i] = true
		}
	}
	return plain, negated
}

// compactBody collapses whitespace in a macro body (preproc_arg) text so the
// structural checks (`if (cond) return`) are insensitive to the macro's layout.
func compactBody(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}

// matchingParen returns the index of the ")" that matches the "(" at open, or -1.
func matchingParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
