package evidence

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Dangerous-function findings are a POLICY check, so the policy's own EXCEPTION
// clauses belong in the detector. The project's white-box security guideline
// allows the banned memory functions when no externally controlled data is
// involved and the memory operation is provably local:
//
//	(1) initializing a fixed-length array or a fixed-length struct,
//	(2) initializing caller memory when the function takes BOTH the pointer and
//	    its size,
//	(3) initializing memory immediately after a heap allocation,
//	(4) a copy whose size is derived from the SOURCE's size,
//	(5) a copy whose source is entirely static string constants (the programmer
//	    is responsible for the destination having room).
//
// Reporting those calls produced findings whose only possible verdict is
// "policy violation, optional to change" (production: `bzero` on a
// `sizeof`-sized array). The check below is deliberately SYNTACTIC and
// conservative: an unrecognized shape stays a finding.
//
// The exemption never applies to assert (intent), and format functions are not
// exempt at all — the guideline's clauses are about memory init/copy.

// initFamily: whole-buffer initialization (clauses 1-3).
var guidelineInitFamily = map[string]bool{"memset": true}

// copyFamily: sized copies (clauses 4-5, plus 5 for the source-literal form).
var guidelineCopyFamily = map[string]bool{
	"memcpy": true, "memmove": true, "wmemcpy": true, "wmemmove": true,
}

// strCopyFamily: length-from-source copies (clause 5 only).
var guidelineStrCopyFamily = map[string]bool{
	"strcpy": true, "strncpy": true, "strcat": true, "strncat": true,
	"wcscpy": true, "wcsncpy": true, "wcscat": true, "wcsncat": true,
}

// paramShape is what the clause checks need to know about a parameter: whether
// it is a pointer (clause 2's destination) and whether it is an integer-ish
// length (clause 2's size).
type paramShape struct {
	isPointer bool
	isInteger bool
}

// allocSite records the last heap allocation assigned to a local.
type allocSite struct {
	line     int
	sizeText string
}

// fnShape holds the per-function facts the clause checks read: parameter
// shapes, every assignment line per variable (so "the last write before the
// call is the allocation" can be proven), and the last allocator assignment.
type fnShape struct {
	params  map[string]paramShape
	assigns map[string][]int
	allocs  map[string]allocSite
}

// buildFnShapes collects the per-function shape facts for one file, keyed by
// the function definition's start line (the same key the call sites resolve
// through db.Function.StartLine).
func buildFnShapes(root parser.Node) map[int]*fnShape {
	out := make(map[int]*fnShape)
	for _, fnDef := range root.FindAll("function_definition") {
		shape := &fnShape{
			params:  make(map[string]paramShape),
			assigns: make(map[string][]int),
			allocs:  make(map[string]allocSite),
		}
		_, names, types := functionParamNames(fnDef)
		for i, name := range names {
			if name == "..." || i >= len(types) {
				continue
			}
			shape.params[name] = classifyParamShape(types[i])
		}
		if body := fnDef.FindFirst("compound_statement"); body != nil {
			collectFnWrites(*body, shape)
		}
		out[fnDef.StartLine()] = shape
	}
	return out
}

// classifyParamShape derives the two facts the clauses need from a normalized
// type spelling ("void *", "size_t", "char *").
func classifyParamShape(spelling string) paramShape {
	t := strings.TrimSpace(spelling)
	shape := paramShape{isPointer: strings.HasSuffix(t, "*")}
	if shape.isPointer {
		return shape
	}
	for _, kw := range []string{"int", "size_t", "ssize_t", "long", "short", "char", "ptr"} {
		if strings.Contains(t, kw) {
			shape.isInteger = true
			break
		}
	}
	return shape
}

// collectFnWrites records every assignment target line and the last allocator
// assignment per variable, in document order.
func collectFnWrites(body parser.Node, shape *fnShape) {
	record := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		// `char *q = malloc(n)` wraps the target in a pointer_declarator, so the
		// lhs is not an identifier node; extractVarName unwraps it.
		name := strings.TrimSpace(extractVarName(lhs))
		if name == "" {
			return
		}
		shape.assigns[name] = append(shape.assigns[name], node.StartLine())
		if alloc, ok := allocatorCall(rhs); ok {
			site := allocSite{line: node.StartLine()}
			if args := getCallArgs(alloc); len(args) > 0 {
				site.sizeText = args[0].Text()
			}
			shape.allocs[name] = site
		}
	}
	for _, assign := range body.FindAll("assignment_expression") {
		record(assign)
	}
	for _, init := range body.FindAll("init_declarator") {
		record(init)
	}
}

// allocatorCall returns the allocation call inside an initializer expression
// (`malloc(n)`, `(T *)calloc(a, b)`), or ok=false when the value is not a
// direct allocator result.
func allocatorCall(expr parser.Node) (parser.Node, bool) {
	inner := expr
	for inner.Kind() == "cast_expression" || inner.Kind() == "parenthesized_expression" {
		var next parser.Node
		for _, c := range inner.NamedChildren() {
			if c.Kind() == "type_descriptor" {
				continue
			}
			next = c
			break
		}
		if next.Kind() == "" {
			return parser.Node{}, false
		}
		inner = next
	}
	if inner.Kind() != "call_expression" {
		return parser.Node{}, false
	}
	if !apikb.IsAllocator(extractCallName(inner)) {
		return parser.Node{}, false
	}
	return inner, true
}

// guidelineExempt reports whether a banned memory call falls into one of the
// guideline's exception clauses. A nil fnShape (a call outside any indexed
// function) never exempts.
func guidelineExempt(call parser.Node, name string, fs *fnShape, stringMacros map[string]bool) bool {
	args := getCallArgs(call)
	switch {
	case guidelineInitFamily[name]:
		if len(args) < 3 {
			return false
		}
		return initCallExempt(call, args[0], args[2], fs)
	case guidelineCopyFamily[name]:
		if len(args) < 3 {
			return false
		}
		src, size := args[1], args[2]
		if sizeDerivedFromSource(size, src) {
			return true
		}
		return staticStringSource(src, stringMacros) && sizeofExpr(size, src)
	case guidelineStrCopyFamily[name]:
		if len(args) < 2 {
			return false
		}
		return staticStringSource(args[1], stringMacros)
	}
	return false
}

// initCallExempt implements clauses 1-3 for a whole-buffer initializer.
func initCallExempt(call, dst, size parser.Node, fs *fnShape) bool {
	if sizeofObject(size, dst) {
		return true
	}
	if fs == nil || dst.Kind() != "identifier" {
		return false
	}
	varName := strings.TrimSpace(dst.Text())
	// Clause 2: caller memory, with the size passed alongside the pointer.
	if ps, ok := fs.params[varName]; ok && ps.isPointer && size.Kind() == "identifier" {
		if ss, ok := fs.params[strings.TrimSpace(size.Text())]; ok && ss.isInteger {
			return true
		}
	}
	// Clause 3: the last write to the variable before this call is a heap
	// allocation, and the size is either the pointee's size or exactly the
	// allocation's size expression.
	if lastWriteLine(fs.assigns[varName], call.StartLine()) == 0 {
		return false
	}
	site, ok := fs.allocs[varName]
	if !ok || site.line == 0 || site.line != lastWriteLine(fs.assigns[varName], call.StartLine()) {
		return false
	}
	if sizeofObject(size, dst) {
		return true
	}
	return site.sizeText != "" && compactText(size.Text()) == compactText(site.sizeText)
}

// lastWriteLine returns the greatest assignment line strictly before limit.
func lastWriteLine(lines []int, limit int) int {
	best := 0
	for _, line := range lines {
		if line < limit && line > best {
			best = line
		}
	}
	return best
}

// sizeofObject reports whether size is `sizeof(<dst>)`, `sizeof(*<dst>)`, or —
// for an address-of destination — `sizeof(<object>)`: the compiler-sized extent
// of exactly the object being initialized (clause 1).
func sizeofObject(size, dst parser.Node) bool {
	st := compactText(size.Text())
	for _, obj := range objectSpellings(dst) {
		if st == "sizeof("+obj+")" || st == "sizeof(*"+obj+")" {
			return true
		}
	}
	return false
}

// objectSpellings returns the spellings of the object a destination expression
// names: `s`, `&s` → {"s", "&s"}, `p->buf` → {"p->buf"}.
func objectSpellings(dst parser.Node) []string {
	t := compactText(dst.Text())
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") && balancedOuterParens(t) {
		t = t[1 : len(t)-1]
	}
	if strings.HasPrefix(t, "&") {
		return []string{t, strings.TrimPrefix(t, "&")}
	}
	return []string{t}
}

// balancedOuterParens reports whether the leading "(" matches the trailing ")"
// (so `(a)+(b)` is not unwrapped as if it were one parenthesized expression).
func balancedOuterParens(t string) bool {
	depth := 0
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i == len(t)-1
			}
		}
	}
	return false
}

// sizeDerivedFromSource reports whether the copy size provably equals the
// SOURCE's size (clause 4): `sizeof(src)`, `sizeof(*src)`, `sizeof(src.f)`,
// `strlen(src)`, `strnlen(src, n)`.
func sizeDerivedFromSource(size, src parser.Node) bool {
	st := compactText(size.Text())
	for _, s := range objectSpellings(src) {
		if st == "sizeof("+s+")" || st == "sizeof(*"+s+")" || st == "sizeof*"+s {
			return true
		}
		// strlen(src) is the source's extent; `+1` keeps the NUL terminator.
		if base := "strlen(" + s + ")"; st == base || st == base+"+1" {
			return true
		}
		if base := "strnlen(" + s + ","; strings.HasPrefix(st, base) {
			return true
		}
	}
	return false
}

// sizeofExpr reports whether size is `sizeof(<expr>)` for the given expression
// — the clause-5 form for a literal source (`memcpy(dst, "abc", sizeof("abc"))`).
func sizeofExpr(size, expr parser.Node) bool {
	st := compactText(size.Text())
	e := compactText(expr.Text())
	return st == "sizeof("+e+")" || st == "sizeof *"+e
}

// staticStringSource reports whether the source expression is entirely static
// string data: a string literal (adjacent literals included) or an object-like
// macro that expands to one.
func staticStringSource(src parser.Node, stringMacros map[string]bool) bool {
	if parser.IsCStringLiteralText(src.Text()) {
		return true
	}
	if src.Kind() == "identifier" {
		return stringMacros[strings.TrimSpace(src.Text())]
	}
	return false
}

// compactText strips all whitespace so two spellings of one expression compare
// equal (`sizeof ( * p )` vs `sizeof(*p)`).
func compactText(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}
