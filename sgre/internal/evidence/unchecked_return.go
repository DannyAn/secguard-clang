package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// UncheckedReturnDetector flags calls to allocation / I/O functions whose
// return value is neither compared directly nor stored into a variable that is
// subsequently checked (CWE-252). This is the C analogue of "missing error
// handling": malloc can return NULL, read/recv can return -1, and ignoring that
// turns a soft failure into a crash or a corruption.
type UncheckedReturnDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUncheckedReturnDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UncheckedReturnDetector {
	return &UncheckedReturnDetector{store: store, parser: p, logger: logger}
}

func (d *UncheckedReturnDetector) Name() string { return "unchecked_return" }

func (d *UncheckedReturnDetector) Domain() string { return "boundary" }

func (d *UncheckedReturnDetector) Capabilities() []string {
	return []string{"null-return", "error-return"}
}

// uncheckedReturnAPIs are calls whose return value must be validated. The
// failure sentinel (NULL or a negative errno value) is irrelevant to the
// detection — only that the value must be checked before use.
var uncheckedReturnAPIs = map[string]bool{
	"malloc": true, "calloc": true, "realloc": true,
	"fopen": true, "fdopen": true, "opendir": true,
	"read": true, "recv": true, "write": true, "send": true,
}

func (d *UncheckedReturnDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// User wrappers that return an unchecked allocation result (e.g.
	// `void *x_malloc(n) { return malloc(n); }`) are passthrough allocators:
	// a call to one must be NULL-checked at the call site exactly like the
	// wrapped allocator. Compute that set once so the per-file pass below
	// treats calls to them as unchecked-return sources too.
	passthrough, err := d.passthroughAllocFuncs(ctx)
	if err != nil {
		return result, err
	}

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		ids := root.FindAll("identifier")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		dos := root.FindAll("do_statement")

		for _, f := range funcs {
			checked := d.checkedVars(ifs, whiles, fors, dos, f)
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				callee := extractCallName(call)
				if !uncheckedReturnAPIs[callee] && !passthrough[callee] {
					continue
				}
				if callResultChecked(call) {
					continue
				}
				// A wrapper that hands the value straight back to its caller
				// (`void *x_malloc(size_t n) { return malloc(n); }`) is a passthrough:
				// the caller -- which sees x_malloc's return -- is responsible for the
				// NULL check, not the wrapper. Flagging the wrapper is a false
				// positive, so skip it.
				if callResultReturned(call) {
					continue
				}
				if v := assignedVarOfCall(call); v != "" {
					if checked[v] {
						continue
					}
					// `void *p = malloc(n); return p;` is a passthrough allocator:
					// the caller checks, so the wrapper's malloc must not be flagged.
					if passthroughReturnVar(v, call.StartLine(), f, returns, ids, checked) {
						continue
					}
				}

				if emitEvent(ctx, d.store, d.logger, "UNCHECKED_RETURN", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
					"function":   extractCallName(call),
					"expression": call.Text(),
					"category":   "unchecked_return",
				}) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// checkedVars returns the set of variable names that are validated somewhere in
// f: compared against a sentinel (`p == NULL`, `ret < 0`), negated (`!p`), or
// used as a bare truthiness condition (`if (p)`). A condition that merely
// dereferences the variable (`if (p->len > 0)`) is NOT a null/error check, so
// it must not mark `p` checked — that would suppress a genuine CWE-252 defect
// (the allocation's failure is never handled before `p` is used). This mirrors
// the planner's ReturnCheckFilter (conditionTestsVar) so the detector and the
// convergence filter agree on what "checked" means.
func (d *UncheckedReturnDetector) checkedVars(ifs, whiles, fors, dos []parser.Node, f *db.Function) map[string]bool {
	set := make(map[string]bool)
	for _, cond := range [][]parser.Node{ifs, whiles, fors, dos} {
		for _, node := range cond {
			if !funcLineRange(f, node.StartLine()) {
				continue
			}
			c := node.ChildByFieldName("condition")
			if c == nil {
				continue
			}
			// For a comparison (`p == NULL` / `ret < 0`), register each operand
			// that IS itself tested; a field/subscript operand is tested as a
			// whole (`e->buffer == NULL` tests e->buffer, not e).
			for _, id := range testedOperands(*c) {
				set[id] = true
			}
			// A bare truthiness condition (`if (p)`) tests p directly.
			if v := bareConditionVar(c); v != "" {
				set[v] = true
			}
		}
	}
	return set
}

// testedOperands returns the variable/member/element expressions that a
// condition's comparison operator directly tests for null/error. `if (p->len > 0)`
// compares p->len, not p, so it yields nothing — the field's value is a length,
// not a sentinel. `if (e->buffer == NULL)` yields e->buffer.
func testedOperands(cond parser.Node) []string {
	var out []string
	for _, b := range cond.FindAll("binary_expression") {
		if !hasCompareOp(b) {
			continue
		}
		for _, child := range b.NamedChildren() {
			switch child.Kind() {
			case "identifier", "field_expression", "subscript_expression":
				out = append(out, child.Text())
			}
		}
	}
	return out
}

// bareConditionVar returns the variable name when a condition is a bare
// identifier (`if (p)`) or its negation (`if (!p)` / `if (!e->buffer)`),
// unwrapping parentheses, or "" for any other shape.
func bareConditionVar(cond *parser.Node) string {
	if cond == nil {
		return ""
	}
	n := *cond
	for n.Kind() == "parenthesized_expression" {
		inner := n.NamedChildren()
		if len(inner) == 0 {
			return ""
		}
		n = inner[0]
	}
	if n.Kind() == "identifier" {
		return n.Text()
	}
	// `if (!p)` / `if (!e->buffer)` — the negation of the variable itself is a
	// null/error check; negating a derived value (`if (!(p->len > 0))`) is not.
	if n.Kind() == "unary_expression" && strings.HasPrefix(strings.TrimSpace(n.Text()), "!") {
		for _, child := range n.NamedChildren() {
			switch child.Kind() {
			case "identifier", "field_expression", "subscript_expression":
				return child.Text()
			}
		}
	}
	return ""
}

// callResultChecked reports whether the call's value is consumed directly by a
// comparison, a `!` negation, or a branch/loop condition — i.e. validated at
// the call site without going through a named variable.
func callResultChecked(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "binary_expression":
			if hasCompareOp(*p) {
				return true
			}
		case "unary_expression":
			if strings.HasPrefix(strings.TrimSpace(p.Text()), "!") {
				return true
			}
		case "if_statement", "while_statement", "for_statement", "do_statement", "switch_statement":
			return true
		case "return_statement", "expression_statement", "compound_statement",
			"declaration", "argument_list", "assignment_expression", "init_declarator":
			return false
		}
	}
	return false
}

// callResultReturned reports whether the call's result flows straight into a
// `return` (possibly through casts/parentheses) without being stored in a
// variable or otherwise consumed first. `void *x_malloc(size_t n) { return
// malloc(n); }` is a passthrough allocator: the caller — which sees x_malloc's
// return value — is responsible for the NULL check, so the wrapper itself must
// not be flagged as an unchecked return.
func callResultReturned(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "parenthesized_expression", "cast_expression":
			continue
		case "return_statement":
			return true
		default:
			return false
		}
	}
	return false
}

// assignedVarOfCall returns the variable the call's result is assigned into
// (via `v = call(...)` or `T v = call(...)`), or "" when the result is not
// stored in a simple named variable.
func assignedVarOfCall(call parser.Node) string {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression", "init_declarator":
			named := p.NamedChildren()
			if len(named) < 2 {
				return ""
			}
			return assignedVariable(named[0])
		case "parenthesized_expression", "cast_expression", "binary_expression",
			"argument_list", "call_expression", "field_expression", "subscript_expression":
			continue
		default:
			return ""
		}
	}
	return ""
}

// hasCompareOp reports whether a binary expression is an equality/relational
// comparison (==, !=, <, <=, >, >=) — the operators used to validate a return
// value (NULL / -1 / 0 / bounds).
func hasCompareOp(expr parser.Node) bool {
	for _, child := range expr.Children() {
		switch child.Kind() {
		case "==", "!=", "<", "<=", ">", ">=":
			return true
		}
	}
	return false
}

// passthroughAllocFuncs returns the set of function names whose body returns an
// unchecked allocation result without checking it — directly (`return malloc(n)`)
// or via an unchecked variable (`void *p = malloc(n); return p;`), or transitively
// (`return other_wrapper(...)`). A call to such a wrapper must be NULL-checked at
// the call site exactly like the allocator it wraps, so the main detection pass
// treats calls to them as unchecked-return sources.
func (d *UncheckedReturnDetector) passthroughAllocFuncs(ctx context.Context) (map[string]bool, error) {
	// returnedSource maps a function name to the set of callee names whose result
	// it returns to its caller.
	returnedSource := make(map[string]map[string]bool)

	add := func(name, callee string) {
		if callee == "" {
			return
		}
		if returnedSource[name] == nil {
			returnedSource[name] = make(map[string]bool)
		}
		returnedSource[name][callee] = true
	}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		returns := root.FindAll("return_statement")
		ids := root.FindAll("identifier")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		dos := root.FindAll("do_statement")

		for _, f := range funcs {
			checked := d.checkedVars(ifs, whiles, fors, dos, f)

			// var -> (callee, assignLine) for `v = callee(...)`.
			calleeOfVar := make(map[string]string)
			lineOfVar := make(map[string]int)
			for _, a := range assigns {
				if !funcLineRange(f, a.StartLine()) {
					continue
				}
				if v, callee := assignCallee(a); v != "" && callee != "" {
					calleeOfVar[v] = callee
					lineOfVar[v] = a.StartLine()
				}
			}
			for _, in := range inits {
				if !funcLineRange(f, in.StartLine()) {
					continue
				}
				if v, callee := assignCallee(in); v != "" && callee != "" {
					calleeOfVar[v] = callee
					lineOfVar[v] = in.StartLine()
				}
			}

			for _, ret := range returns {
				if !funcLineRange(f, ret.StartLine()) {
					continue
				}
				if callee := returnedCalleeName(ret); callee != "" {
					add(f.Name, callee)
					continue
				}
				if v := returnedVar(ret); v != "" {
					if callee, ok := calleeOfVar[v]; ok && passthroughReturnVar(v, lineOfVar[v], f, returns, ids, checked) {
						add(f.Name, callee)
					}
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}

	// Monotone fixpoint: a function is a passthrough allocator if it returns a
	// call to an unchecked-return API, or to another passthrough allocator.
	passthrough := make(map[string]bool)
	changed := true
	for changed {
		changed = false
		for name, callees := range returnedSource {
			if passthrough[name] {
				continue
			}
			for callee := range callees {
				if uncheckedReturnAPIs[callee] || passthrough[callee] {
					passthrough[name] = true
					changed = true
					break
				}
			}
		}
	}
	return passthrough, nil
}

// passthroughReturnVar reports whether variable v, assigned at assignLine in f,
// is later returned by f without being null-checked or otherwise used in between.
// `void *x_malloc(n) { void *p = malloc(n); return p; }` is a passthrough
// allocator: the caller checks, so f's own unchecked-return call must not be
// flagged (and f itself becomes a source the caller must check). A use of v
// between the assignment and the return (e.g. `p[0] = 'x'`) is a genuine
// unchecked-use defect, so it must NOT count as a passthrough.
func passthroughReturnVar(v string, assignLine int, f *db.Function, returns, ids []parser.Node, checked map[string]bool) bool {
	if v == "" || checked[v] {
		return false
	}
	retLine := -1
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) || ret.StartLine() <= assignLine {
			continue
		}
		if returnedVar(ret) == v {
			retLine = ret.StartLine()
			break
		}
	}
	if retLine < 0 {
		return false
	}
	for _, id := range ids {
		if id.Text() != v || !funcLineRange(f, id.StartLine()) {
			continue
		}
		if id.StartLine() > assignLine && id.StartLine() < retLine {
			return false
		}
	}
	return true
}

// returnedVar returns the identifier a return statement returns (`return v`),
// else "" (for `return g()`, `return p->x`, `return NULL`, ...).
func returnedVar(ret parser.Node) string {
	for _, child := range ret.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

// assignCallee returns (varName, calleeName) for an assignment/initializer of the
// form `v = callee(...)` / `T v = callee(...)` (RHS possibly cast/parenthesised).
// It returns ("", "") for any other RHS shape.
func assignCallee(node parser.Node) (string, string) {
	children := node.NamedChildren()
	if len(children) < 2 {
		return "", ""
	}
	v := assignedVariable(children[0])
	if v == "" {
		return "", ""
	}
	return v, calleeOfExpr(children[1])
}


// returnedCalleeName returns the called function name when a return statement
// directly returns a call (`return g(...)`), unwrapping casts/parentheses; else "".
func returnedCalleeName(ret parser.Node) string {
	for _, child := range ret.NamedChildren() {
		if name := calleeOfExpr(child); name != "" {
			return name
		}
	}
	return ""
}

// calleeOfExpr returns the called function name when expr is a call_expression
// possibly wrapped in casts/parentheses, else "".
func calleeOfExpr(expr parser.Node) string {
	switch expr.Kind() {
	case "call_expression":
		return extractCallName(expr)
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if name := calleeOfExpr(c); name != "" {
				return name
			}
		}
	}
	return ""
}
