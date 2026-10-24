package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// summaryQuerier implements graph.SummaryQuerier by reusing the existing
// null-return summary (computeRetNullable). The other dimensions (interval,
// taint, capacity) are placeholders until their fixpoints are promoted to
// graph-level utilities — the skeleton establishes the interface so
// detectors can start consuming it.
type summaryQuerier struct {
	store    db.Store
	parser   *parser.Parser
	cfgCache *graph.CFGCache
	// memo memoizes SummaryOf results per function name so a call-heavy
	// detector does not re-analyze the same callee body for every call site.
	memo map[string]graph.Summary
	// visiting is the cycle guard for the recursive SummaryOf: a recursive
	// callee resolves to TriUnknown on the Null dimension rather than
	// looping forever.
	visiting map[string]bool
}

// NewSummaryQuerier builds the per-scan SummaryQuerier.
func NewSummaryQuerier(store db.Store, p *parser.Parser, cfgCache *graph.CFGCache) graph.SummaryQuerier {
	return &summaryQuerier{
		store:    store,
		parser:   p,
		cfgCache: cfgCache,
		memo:     make(map[string]graph.Summary),
		visiting: make(map[string]bool),
	}
}

// SummaryOf returns the Summary for the named function. The Null dimension
// is computed by a bounded recursive descent over the callee's return
// statements (literal NULL → TriYes, call to another named function →
// recurse with cycle guard, anything else → TriNo when every return is
// provably non-null, TriUnknown otherwise). Interval / Taint / Capacity are
// placeholders reporting their "unknown" shape so a caller must not rely on
// them until their fixpoints land.
func (q *summaryQuerier) SummaryOf(ctx context.Context, funcName string) (graph.Summary, bool) {
	if funcName == "" {
		return graph.Summary{}, false
	}
	if s, ok := q.memo[funcName]; ok {
		return s, true
	}
	s := graph.Summary{
		Function: funcName,
		Null:     q.nullOf(ctx, funcName),
		Interval: graph.Interval{Top: true},
		Taint:    graph.TriUnknown,
		Capacity: -1,
	}
	q.memo[funcName] = s
	return s, true
}

// SummaryByID is SummaryOf keyed by function ID.
func (q *summaryQuerier) SummaryByID(ctx context.Context, fn *db.Function) (graph.Summary, bool) {
	if fn == nil {
		return graph.Summary{}, false
	}
	return q.SummaryOf(ctx, fn.Name)
}

// nullOf resolves the Null dimension for funcName: TriYes when a return
// statement provably yields NULL, TriNo when every return provably does
// not, TriUnknown otherwise (external / unparseable / recursive / mixed).
func (q *summaryQuerier) nullOf(ctx context.Context, funcName string) graph.Tri {
	if q.store == nil || q.parser == nil {
		return graph.TriUnknown
	}
	if q.visiting[funcName] {
		return graph.TriUnknown
	}
	q.visiting[funcName] = true
	defer delete(q.visiting, funcName)

	fn, err := q.store.GetFunctionByName(ctx, funcName)
	if err != nil || fn == nil {
		return graph.TriUnknown
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return graph.TriUnknown
	}
	body, _ := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return graph.TriUnknown
	}

	sawReturn := false
	sawUnknown := false
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		sawReturn = true
		expr := children[0]
		// A literal NULL / 0 in a pointer-return function is a proven null
		// return (the return-type gate: bare 0 in an int-return function is
		// the integer zero, not a null pointer; we do not yet consult the
		// declared return type here, so we treat both as candidate nulls and
		// let the caller's type knowledge refine).
		if isNullLiteralNode(expr) {
			return graph.TriYes
		}
		if expr.Kind() == "call_expression" {
			callee := expr.ChildByFieldName("function")
			if callee != nil && callee.Kind() == "identifier" {
				sub, _ := q.SummaryOf(ctx, callee.Text())
				if sub.Null == graph.TriYes {
					return graph.TriYes
				}
				if sub.Null == graph.TriUnknown {
					sawUnknown = true
				}
				continue
			}
			sawUnknown = true
			continue
		}
		// Any other return expression shape is conservatively unknown: a
		// parameter, a field read, an arithmetic expression — any of them
		// could carry a null without a local proof.
		if !isProvablyNonNullExpr(expr) {
			sawUnknown = true
		}
	}
	if !sawReturn {
		return graph.TriUnknown
	}
	if sawUnknown {
		return graph.TriUnknown
	}
	return graph.TriNo
}

// isProvablyNonNullExpr reports whether expr is a syntactic non-null shape:
// a string literal, a numeric literal other than 0, the address-of operator,
// or a composite literal.
func isProvablyNonNullExpr(expr parser.Node) bool {
	switch expr.Kind() {
	case "string_literal", "char_literal", "concatenated_string":
		return true
	case "number_literal":
		return expr.Text() != "0"
	case "unary_expression", "pointer_expression":
		// &x is never null.
		for _, c := range expr.Children() {
			if c.Kind() == "&" {
				return true
			}
		}
		return false
	}
	return false
}
