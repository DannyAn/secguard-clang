package planner

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// IntOverflowGuardFilter converges the integer-overflow stream with a
// path-sensitive guard check: a size_calc_overflow candidate (malloc(n * size))
// is dropped when EVERY variable operand of the size expression is bounded by a
// preceding `if (op < CONST)` / `if (op <= CONST)` guard to a small constant
// (< guardMaxBound), so the product cannot overflow a 32-bit integer.
//
// This is deliberately conservative: it only drops when the bound is small
// enough that the product provably fits (guardMaxBound² < 2^31), so it cannot
// introduce a false negative from an imprecise bound. It adds path sensitivity
// to a type that previously ran only the call-reach + safe-function chain.
type IntOverflowGuardFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewIntOverflowGuardFilter(store db.Store, p *parser.Parser, logger *log.Logger) *IntOverflowGuardFilter {
	return &IntOverflowGuardFilter{store: store, parser: p, logger: logger}
}

func (f *IntOverflowGuardFilter) Name() string { return "int_overflow_guard" }

// guardMaxBound is the largest constant a guard may bound an operand to for the
// product to still provably avoid overflow: 32768² = 2^30 < 2^31.
const guardMaxBound = 32768

func (f *IntOverflowGuardFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}
	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	// Parse each candidate function body once and reuse it for both the range
	// analysis and the per-candidate guard bounds: operandBounds previously
	// created a fresh fileParseCache per candidate, re-reading and re-parsing
	// the same file once per candidate (an O(candidates × parse) cost).
	cache := newFileParseCache(f.parser)
	bodies := make(map[int64]parser.Node, len(byFunc))
	for fid := range byFunc {
		fn := fnByID[fid]
		if fn == nil {
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, _ := cache.get(file, fn)
		if body.Kind() == "compound_statement" {
			bodies[fid] = body
		}
	}
	rangeFlows := f.buildRangeFlows(byFunc, fnByID, bodies)

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		// The variable-operand size patterns (product, add-const, mul-const)
		// and general integer arithmetic share the same bound check: every
		// variable operand bounded by a preceding `if (op < CONST)` guard OR a
		// cross-assignment constant interval to a small bound makes the
		// arithmetic provably non-overflowing (guardMaxBound² < 2^31, and a
		// small bound keeps a + const and a * const well below SIZE_MAX).
		switch c.Category {
		case "size_calc_overflow", "size_mul_const_overflow", "integer_overflow":
		default:
			kept = append(kept, c)
			continue
		}
		operands := identifiersInExpr(c.VariableName)
		if len(operands) == 0 {
			kept = append(kept, c)
			continue
		}

		bounds := f.operandBounds(c, bodies)
		flow := rangeFlows[c.FunctionID]
		allBounded := true
		for _, op := range operands {
			if b, ok := bounds[op]; ok && b > 0 && b < guardMaxBound {
				continue
			}
			// No guard: fall back to the interval engine. op ∈ [lo, hi] with
			// 0 <= lo and hi < guardMaxBound proves op is a small non-negative
			// constant on every path (`size_t n = 10; malloc(n * n)`).
			if flow != nil {
				if r := flow.at(op, c.Line); r.lo >= 0 && r.hi < guardMaxBound {
					continue
				}
			}
			allBounded = false
			break
		}
		if allBounded {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("size operands are bounded to < %d, so the arithmetic cannot overflow", guardMaxBound))
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

// buildRangeFlows runs the interval analysis once per candidate function,
// reusing the already-parsed bodies.
func (f *IntOverflowGuardFilter) buildRangeFlows(byFunc map[int64][]Candidate, fnByID map[int64]*db.Function, bodies map[int64]parser.Node) map[int64]*rangeFlow {
	flows := make(map[int64]*rangeFlow, len(byFunc))
	for fid := range byFunc {
		fn := fnByID[fid]
		if fn == nil {
			continue
		}
		body, ok := bodies[fid]
		if !ok {
			continue
		}
		flows[fid] = analyzeRanges(fn, body)
	}
	return flows
}

// operandBounds returns, per variable operand, the smallest constant bound found
// in a DOMINATING guard (`if (op < CONST)` / `if (op <= CONST)`) whose bounded
// value is not reassigned before the allocation. A missing/non-dominating/
// invalidated guard means unbounded (not in the map).
func (f *IntOverflowGuardFilter) operandBounds(c Candidate, bodies map[int64]parser.Node) map[string]int64 {
	bounds := make(map[string]int64)
	body, ok := bodies[c.FunctionID]
	if !ok {
		return bounds
	}

	type guardSite struct {
		cond      parser.Node
		line      int
		bodyStart int
		bodyEnd   int
	}
	var sites []guardSite
	for _, ifNode := range body.FindAll("if_statement") {
		if ifNode.StartLine() >= c.Line {
			continue // only guards before the allocation
		}
		cond := ifNode.ChildByFieldName("condition")
		cons := ifNode.ChildByFieldName("consequence")
		if cond == nil || cons == nil {
			continue
		}
		sites = append(sites, guardSite{*cond, ifNode.StartLine(), cons.StartLine(), cons.EndLine()})
	}
	// A while/for condition guards its loop body the same way an if-consequence
	// guards its body.
	for _, loopNode := range append(body.FindAll("while_statement"), body.FindAll("for_statement")...) {
		if loopNode.StartLine() >= c.Line {
			continue
		}
		cond := loopNode.ChildByFieldName("condition")
		loopBody := loopNode.ChildByFieldName("body")
		if cond == nil || loopBody == nil {
			continue
		}
		sites = append(sites, guardSite{*cond, loopNode.StartLine(), loopBody.StartLine(), loopBody.EndLine()})
	}

	for _, site := range sites {
		// The guard must DOMINATE the allocation: the candidate line must lie
		// inside the guard's body (true branch). A guard in a sibling branch, or
		// one whose body has already been exited, is not a bound.
		if c.Line < site.bodyStart || c.Line > site.bodyEnd {
			continue
		}
		for _, gb := range guardBounds(site.cond) {
			// A whole-variable reassignment of the operand between the guard and
			// the allocation invalidates the bound.
			if reassignedBetween(body, gb.operand, site.line, c.Line) {
				continue
			}
			if prev, seen := bounds[gb.operand]; !seen || gb.bound < prev {
				bounds[gb.operand] = gb.bound
			}
		}
	}
	return bounds
}

// reassignedBetween reports whether op is whole-variable reassigned at any line
// strictly between from and to.
func reassignedBetween(body parser.Node, op string, from, to int) bool {
	for _, assign := range body.FindAll("assignment_expression") {
		line := assign.StartLine()
		if line <= from || line >= to {
			continue
		}
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" && children[0].Text() == op {
			return true
		}
	}
	return false
}

// guardBound is one operand upper bound a guard condition establishes.
type guardBound struct {
	operand string
	bound   int64
}

// guardBounds returns the operand upper bounds a guard condition establishes:
// `op < N` / `op <= N` / `N > op` / `N >= op`, and a conjunction
// (`a < N && b < M`) yields both. A field/subscript operand is kept whole so
// `if (s->len < 100)` bounds "s->len" (not "s" and "len" separately).
func guardBounds(cond parser.Node) []guardBound {
	for cond.Kind() == "parenthesized_expression" {
		children := cond.NamedChildren()
		if len(children) == 0 {
			return nil
		}
		cond = children[0]
	}
	if cond.Kind() != "binary_expression" {
		return nil
	}
	if op := binaryOperatorToken(cond); op == "&&" {
		var out []guardBound
		for _, child := range cond.NamedChildren() {
			out = append(out, guardBounds(child)...)
		}
		return out
	}
	op := binaryOperatorToken(cond)
	if op != "<" && op != "<=" && op != ">" && op != ">=" {
		return nil
	}
	children := cond.NamedChildren()
	if len(children) != 2 {
		return nil
	}
	// Determine which side is the variable operand and which the constant,
	// normalising a reversed comparison (`N > op` → `op < N`).
	varOperand, constOperand := children[0], children[1]
	if isConstOperand(children[0]) && !isConstOperand(children[1]) {
		varOperand, constOperand = children[1], children[0]
		if op == ">" {
			op = "<"
		} else if op == ">=" {
			op = "<="
		}
	} else if isConstOperand(children[0]) || !isConstOperand(children[1]) {
		return nil
	}
	name := operandPathName(varOperand)
	if name == "" {
		return nil
	}
	limit, err := parseIntLiteral(constOperand.Text())
	if err != nil {
		return nil
	}
	// `op < N` establishes op <= N-1; `op <= N` establishes op <= N. The upper
	// bound used for the < guardMaxBound check.
	if op == "<" {
		limit--
	}
	return []guardBound{{operand: name, bound: limit}}
}

// binaryOperatorToken returns the operator token of a binary_expression.
func binaryOperatorToken(node parser.Node) string {
	for _, child := range node.Children() {
		switch child.Kind() {
		case "<", "<=", ">", ">=", "&&", "||", "==", "!=", "+", "-", "*", "/", "%":
			return child.Kind()
		}
	}
	return ""
}

// isConstOperand reports whether node is a numeric literal (possibly wrapped in
// parentheses or a cast).
func isConstOperand(node parser.Node) bool {
	switch node.Kind() {
	case "number_literal":
		return true
	case "parenthesized_expression", "cast_expression":
		for _, c := range node.NamedChildren() {
			if isConstOperand(c) {
				return true
			}
		}
	}
	return false
}

// operandPathName returns the tracked variable name of a guard operand: a bare
// identifier, or a field/subscript path kept whole.
func operandPathName(node parser.Node) string {
	switch node.Kind() {
	case "identifier", "field_expression", "subscript_expression":
		return node.Text()
	}
	return ""
}

func parseIntLiteral(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "u")
	s = strings.TrimSuffix(s, "U")
	s = strings.TrimSuffix(s, "l")
	s = strings.TrimSuffix(s, "L")
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

// identifiersInExpr returns the variable operands of an arithmetic expression
// text: a bare identifier or a field/subscript path ("s->len", "a[i]") is one
// operand. Numeric literals, `sizeof`, and C type keywords are dropped, and `->`/
// `.`/`[`/`]` are kept as part of the operand so a field guard (`s->len < 100`)
// matches the operand the detector recorded.
func identifiersInExpr(text string) []string {
	var ids []string
	var cur strings.Builder
	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" || s == "sizeof" || parser.IsCTypeKeyword(s) {
			return
		}
		if _, err := parseIntLiteral(s); err == nil {
			return // a pure numeric literal is not a variable operand
		}
		ids = append(ids, s)
	}
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case ' ', '\t', '\n', '(', ')', '*', '+', '/', '%', ',', ';', '=':
			flush()
		case '-':
			// `->` is pointer member access (kept whole); a bare `-` is the
			// subtraction operator (a separator).
			if i+1 < len(runes) && runes[i+1] == '>' {
				cur.WriteRune('-')
				cur.WriteRune('>')
				i++
			} else {
				flush()
			}
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return ids
}
