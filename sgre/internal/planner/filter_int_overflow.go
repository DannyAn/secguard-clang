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
	rangeFlows := f.buildRangeFlows(ctx, byFunc)

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
		case "size_calc_overflow", "size_add_overflow", "size_mul_const_overflow", "integer_overflow":
		default:
			kept = append(kept, c)
			continue
		}
		operands := identifiersInExpr(c.VariableName)
		if len(operands) == 0 {
			kept = append(kept, c)
			continue
		}

		bounds := f.operandBounds(ctx, c)
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

// buildRangeFlows runs the interval analysis once per candidate function.
func (f *IntOverflowGuardFilter) buildRangeFlows(ctx context.Context, byFunc map[int64][]Candidate) map[int64]*rangeFlow {
	flows := make(map[int64]*rangeFlow, len(byFunc))
	cache := newFileParseCache(f.parser)
	for fid := range byFunc {
		fn, err := f.store.GetFunctionByID(ctx, fid)
		if err != nil || fn == nil {
			continue
		}
		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			continue
		}
		body, _ := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		flows[fid] = analyzeRanges(fn, body)
	}
	return flows
}

// operandBounds returns, per variable operand, the smallest constant bound found
// in a preceding guard (`if (op < CONST)` / `if (op <= CONST)`). A missing guard
// means unbounded (not in the map).
func (f *IntOverflowGuardFilter) operandBounds(ctx context.Context, c Candidate) map[string]int64 {
	bounds := make(map[string]int64)
	fn, err := f.store.GetFunctionByID(ctx, c.FunctionID)
	if err != nil || fn == nil {
		return bounds
	}
	file, err := f.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return bounds
	}
	body, _ := newFileParseCache(f.parser).get(file, fn)
	if body.Kind() != "compound_statement" {
		return bounds
	}

	for _, ifNode := range body.FindAll("if_statement") {
		if ifNode.StartLine() >= c.Line {
			continue // only guards before the allocation
		}
		cond := ifNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		op, limit, ok := boundComparison(*cond)
		if !ok {
			continue
		}
		if prev, seen := bounds[op]; !seen || limit < prev {
			bounds[op] = limit
		}
	}
	return bounds
}

// boundComparison returns (operand, bound, ok) when cond is `op < N` or
// `op <= N` for a numeric literal N. The operator tokens (<, <=) are ANONYMOUS
// tree-sitter nodes, so they only appear in Children(), not NamedChildren().
func boundComparison(cond parser.Node) (string, int64, bool) {
	// Unwrap a parenthesized condition: tree-sitter wraps `if (n < 100)`'s
	// condition in a parenthesized_expression.
	for cond.Kind() == "parenthesized_expression" {
		children := cond.NamedChildren()
		if len(children) == 0 {
			return "", 0, false
		}
		cond = children[0]
	}
	if cond.Kind() != "binary_expression" {
		return "", 0, false
	}
	op := ""
	var lhs, rhs string
	for _, child := range cond.Children() {
		switch child.Kind() {
		case "<", "<=":
			op = child.Kind()
		case "identifier":
			if lhs == "" {
				lhs = child.Text()
			} else {
				rhs = child.Text()
			}
		case "number_literal":
			rhs = child.Text()
		}
	}
	if op == "" || lhs == "" || rhs == "" {
		return "", 0, false
	}
	limit, err := parseIntLiteral(rhs)
	if err != nil {
		return "", 0, false
	}
	return lhs, limit, true
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

// identifiersInExpr returns the bare-identifier operands of an arithmetic
// expression text (e.g. "n * size" -> ["n","size"]).
func identifiersInExpr(text string) []string {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
	var ids []string
	for _, f := range fields {
		if bareIdentVar(f) != "" {
			ids = append(ids, f)
		}
	}
	return ids
}
