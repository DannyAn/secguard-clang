package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// boundedReturnSummary maps a function name to the 0-based index of the
// parameter its return value is provably bounded by — the "capacity" parameter:
//
//	uint32_t add_x(char *buf, uint32_t size) {
//	    return snprintf_truncated_s(buf, size, "...");  // return <= size (arg 1)
//	}
//
// is bounded-return at index 1. The integer-overflow detector uses this
// interprocedural fact to prove an accumulator built from such returns
// (`length += add_x(...)`) stays within the buffer size, so a later
// `size - length` subtraction cannot underflow.
type boundedReturnSummary map[string]int

// capArg resolves the capacity-argument index of a function, first from the
// auto-summarized wrappers and then from the apikb contract table (built-in
// snprintf_truncated_s / sprintf_s / ... plus config-registered wrappers).
func (s boundedReturnSummary) capArg(name string) (int, bool) {
	if idx, ok := s[name]; ok {
		return idx, true
	}
	return apikb.TruncatingWrapperCapArg(name)
}

// buildBoundedReturnSummary computes, over every indexed function, the
// truncating-wrapper contract. It is the interprocedural return-boundedness
// summary — the analogue of the planner's non-zero return summary, but for
// "returns a value <= its capacity argument" instead of "returns non-zero".
//
// It is conservative in the one direction that matters: a function is summarized
// only when EVERY return provably forwards a known bounded-return callee's result
// with the SAME parameter passed through as that callee's capacity argument. Any
// undeterminable return (a literal, an arithmetic expression, an unresolved call,
// a void return) leaves the function unsummarized, so a real underflow is never
// suppressed by an imprecise summary. A bounded fixpoint closes multi-hop chains
// (add_hostname -> add_host -> snprintf_truncated_s).
func buildBoundedReturnSummary(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) boundedReturnSummary {
	summary := boundedReturnSummary{}
	for pass := 0; pass < 16; pass++ {
		changed := false
		err := forEachFile(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
			funcDefs := root.FindAll("function_definition")
			bodies := functionBodyMap(funcDefs)
			inits := root.FindAll("init_declarator")
			assigns := root.FindAll("assignment_expression")
			for _, f := range funcs {
				if _, done := summary[f.Name]; done {
					continue
				}
				body := bodies[f.StartLine]
				if body.Kind() != "compound_statement" {
					continue
				}
				params := extractFunctionParamsFrom(funcDefs, f.StartLine)
				if idx, ok := summarizeWrapper(f, body, params, inits, assigns, summary); ok {
					summary[f.Name] = idx
					changed = true
				}
			}
		})
		if err != nil || !changed {
			break
		}
	}
	return summary
}

// summarizeWrapper reports whether fn is a truncating wrapper and, if so, the
// 0-based index of the parameter every return is bounded by. A candidate index
// must agree across ALL returns: if one return is bounded by arg 1 and another by
// arg 2, the function is left unsummarized.
func summarizeWrapper(f *db.Function, body parser.Node, params []string, inits, assigns []parser.Node, summary boundedReturnSummary) (int, bool) {
	if len(params) == 0 {
		return 0, false
	}
	returns := body.FindAll("return_statement")
	if len(returns) == 0 {
		return 0, false
	}
	assigned := singleAssignments(f, inits, assigns)
	candidate := -1
	for _, ret := range returns {
		expr := returnExprNode(ret)
		if expr == nil {
			return 0, false
		}
		pi := boundedByParam(*expr, params, assigned, summary)
		if pi < 0 {
			return 0, false
		}
		if candidate < 0 {
			candidate = pi
		} else if candidate != pi {
			return 0, false
		}
	}
	if candidate < 0 {
		return 0, false
	}
	return candidate, true
}

// boundedByParam reports which parameter index bounds the return expression, or
// -1. It recognizes two provable shapes:
//
//  1. `return <bounded-return-call>(..., param, ...)` — the callee's capacity
//     argument is exactly one of f's parameters (the forwarding wrapper).
//  2. `return local` where local is assigned once from such a call
//     (`uint32_t n = snprintf_truncated_s(buf, size, ...); return n;`).
func boundedByParam(expr parser.Node, params []string, assigned map[string]parser.Node, summary boundedReturnSummary) int {
	expr = unwrapExprNode(expr)
	switch expr.Kind() {
	case "call_expression":
		return forwardBoundedBy(expr, params, summary)
	case "identifier":
		if v, ok := assigned[expr.Text()]; ok {
			return boundedByParam(v, params, assigned, summary)
		}
	}
	return -1
}

// forwardBoundedBy resolves the parameter index a call forwards as its capacity
// argument: `f(..., p, ...)` where f is bounded-return at capIdx and p is one of
// the caller's parameters.
func forwardBoundedBy(call parser.Node, params []string, summary boundedReturnSummary) int {
	name := extractCallName(call)
	capIdx, ok := summary.capArg(name)
	if !ok {
		return -1
	}
	args := callNamedArguments(call)
	if capIdx >= len(args) {
		return -1
	}
	return paramIndex(args[capIdx], params)
}

// paramIndex returns the index of the parameter whose text equals the argument
// node (a bare identifier), or -1.
func paramIndex(node parser.Node, params []string) int {
	n := unwrapExprNode(node)
	if n.Kind() != "identifier" {
		return -1
	}
	for i, p := range params {
		if p == n.Text() {
			return i
		}
	}
	return -1
}

// singleAssignments records the unambiguous single assignment of each local
// (`uint32_t n = expr;` or `n = expr;`), including call-expression values so a
// forwarding wrapper that stores a truncating call result in a local first is
// still summarized.
func singleAssignments(f *db.Function, inits, assigns []parser.Node) map[string]parser.Node {
	out := make(map[string]parser.Node)
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		if name, expr := declaratorAssignment(init); name != "" && expr != nil {
			out[name] = *expr
		}
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 || children[0].Kind() != "identifier" {
			continue
		}
		rhs := unwrapExprNode(children[1])
		switch rhs.Kind() {
		case "binary_expression", "identifier", "call_expression":
			out[children[0].Text()] = rhs
		}
	}
	return out
}

// returnExprNode returns the single expression node a return_statement returns,
// or nil for a bare `return;`.
func returnExprNode(ret parser.Node) *parser.Node {
	named := ret.NamedChildren()
	if len(named) == 0 {
		return nil
	}
	return &named[0]
}

// boundedAccumulators returns the local variables that are provably bounded by a
// buffer-size expression, keyed by accumulator name -> that size expression's
// normalized text. A local `length` qualifies iff every write is an accumulation
// `length += f(...)` / `length = length + f(...)` where f is a bounded-return
// wrapper and its capacity argument is either the full buffer (`total`, allowed
// only before length has grown) or the remaining space (`total - length`), with a
// consistent `total` across all writes. The capacity-argument check is what makes
// this precise: `length += f(buf, 100); length += g(buf, 100)` (two full-buffer
// writes) is NOT bounded, because 2*100 may exceed total.
func boundedAccumulators(assigns []parser.Node, f *db.Function, summary boundedReturnSummary) map[string]string {
	out := make(map[string]string)
	disqualified := make(map[string]bool)
	totalOf := make(map[string]string)
	grown := make(map[string]bool)

	disqualify := func(name string) {
		disqualified[name] = true
		delete(out, name)
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 || children[0].Kind() != "identifier" {
			continue
		}
		name := children[0].Text()

		// `name = 0` is a constant-zero reset: name is back to 0, so the bounded
		// invariant still holds (name <= total). It resets growth but keeps the
		// consistent total.
		if isConstantZero(children[1]) {
			grown[name] = false
			continue
		}

		call, accumulate, ok := accumulateWrite(assign, name)
		if !ok {
			disqualify(name)
			continue
		}
		if disqualified[name] {
			continue
		}

		capIdx, ok := summary.capArg(extractCallName(call))
		if !ok {
			disqualify(name)
			continue
		}
		args := callNamedArguments(call)
		if capIdx >= len(args) {
			disqualify(name)
			continue
		}

		total, full, ok := capacityTotal(args[capIdx], name)
		if !ok || total == "" {
			disqualify(name)
			continue
		}
		if prev, seen := totalOf[name]; seen && prev != total {
			disqualify(name)
			continue
		}
		totalOf[name] = total
		if accumulate && full && grown[name] {
			// A second full-buffer ACCUMULATION may exceed total (name was already
			// grown once), so the invariant no longer holds.
			disqualify(name)
			continue
		}
		grown[name] = true
		out[name] = total
	}
	return out
}

// accumulateWrite returns the call_expression written into name, and whether the
// write ACCUMULATES (`+=` / `= name + ...`) rather than overwrites (`= f(...)`).
// The flag matters because two full-buffer accumulations can exceed total, while
// an overwrite always lands at the callee's bounded return value.
func accumulateWrite(assign parser.Node, name string) (parser.Node, bool, bool) {
	children := assign.NamedChildren()
	if len(children) < 2 {
		return parser.Node{}, false, false
	}
	if op := assign.ChildByFieldName("operator"); op != nil && op.Text() == "+=" {
		rhs := unwrapExprNode(children[1])
		if rhs.Kind() == "call_expression" {
			return rhs, true, true
		}
		return parser.Node{}, false, false
	}
	rhs := unwrapExprNode(children[1])
	if rhs.Kind() == "binary_expression" && arithOperator(rhs) == "+" {
		rc := rhs.NamedChildren()
		if len(rc) == 2 && rc[0].Kind() == "identifier" && rc[0].Text() == name {
			for _, c := range rc {
				if c.Kind() == "call_expression" {
					return c, true, true
				}
			}
		}
		return parser.Node{}, false, false
	}
	// `name = f(...)`: a plain overwrite from a bounded-return call. The result
	// replaces name and is <= the capacity, so it is always bounded.
	if rhs.Kind() == "call_expression" {
		return rhs, false, true
	}
	return parser.Node{}, false, false
}

// isConstantZero reports whether node is the integer literal 0 (possibly
// parenthesized or cast).
func isConstantZero(node parser.Node) bool {
	node = unwrapExprNode(node)
	if node.Kind() != "number_literal" {
		return false
	}
	s := strings.TrimSpace(node.Text())
	s = strings.TrimRight(s, "uUlL")
	return s == "0"
}

// capacityTotal interprets an accumulator write's capacity argument. It must be
// either the remaining space `total - name` (full=false) or the full buffer
// `total` (full=true, valid only before the accumulator has grown). It returns
// the normalized `total` text; a shape that is neither is (ok=false).
func capacityTotal(cap parser.Node, name string) (total string, full bool, ok bool) {
	cap = unwrapExprNode(cap)
	if cap.Kind() == "binary_expression" && arithOperator(cap) == "-" {
		kids := cap.NamedChildren()
		if len(kids) == 2 && exprTextKey(kids[1]) == name {
			return exprTextKey(kids[0]), false, true
		}
		return "", false, false
	}
	return exprTextKey(cap), true, true
}
