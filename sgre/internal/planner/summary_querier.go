package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// summaryQuerier implements graph.SummaryQuerier by reusing the existing
// null-return summary (computeRetNullable) and the taint summary cache. The
// Interval dimension is computed per-function from the return statements
// (a literal → const interval; an identifier → the range flow's interval at
// the return line; a call → the callee's summary interval); the Capacity
// dimension is a placeholder until the capacity fixpoint lands.
type summaryQuerier struct {
	store      db.Store
	parser     *parser.Parser
	cfgCache   *graph.CFGCache
	taintCache *taintSummaryCache
	// memo memoizes SummaryOf results per function name so a call-heavy
	// detector does not re-analyze the same callee body for every call site.
	memo map[string]graph.Summary
	// visiting is the cycle guard for the recursive SummaryOf: a recursive
	// callee resolves to TriUnknown on the Null dimension rather than
	// looping forever.
	visiting map[string]bool
}

// NewSummaryQuerier builds the per-scan SummaryQuerier. taintCache may be
// nil (the Taint dimension then stays TriUnknown for every function).
func NewSummaryQuerier(store db.Store, p *parser.Parser, cfgCache *graph.CFGCache, taintCache *taintSummaryCache) graph.SummaryQuerier {
	return &summaryQuerier{
		store:      store,
		parser:     p,
		cfgCache:   cfgCache,
		taintCache: taintCache,
		memo:       make(map[string]graph.Summary),
		visiting:   make(map[string]bool),
	}
}

// SummaryOf returns the Summary for the named function. The Null dimension
// is computed by a bounded recursive descent over the callee's return
// statements (literal NULL → TriYes, call to another named function →
// recurse with cycle guard, anything else → TriNo when every return is
// provably non-null, TriUnknown otherwise). The Interval dimension is the
// join of every return expression's interval (literal → const, identifier →
// range flow at the return line, call → the callee's summary interval).
// Taint is read from the shared taintSummaryCache. Capacity is a
// placeholder reporting -1 until the capacity fixpoint lands.
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
		Interval: q.intervalOf(ctx, funcName),
		Taint:    q.taintOf(ctx, funcName),
		Capacity: q.capacityOf(ctx, funcName),
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

// intervalOf resolves the Interval dimension for funcName: the join of every
// return expression's interval. A literal return contributes a const
// interval; an identifier contributes the range flow's interval at the
// return line; a call contributes the callee's summary interval. The
// boolean is false when no return yields a tighter-than-top fact.
func (q *summaryQuerier) intervalOf(ctx context.Context, funcName string) graph.Interval {
	if q.store == nil || q.parser == nil {
		return graph.Interval{Top: true}
	}
	fn, err := q.store.GetFunctionByName(ctx, funcName)
	if err != nil || fn == nil {
		return graph.Interval{Top: true}
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return graph.Interval{Top: true}
	}
	body, _ := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return graph.Interval{Top: true}
	}
	flow := analyzeRangesWithCalls(q.cfgCache, fn, body, nil)
	if flow == nil {
		return graph.Interval{Top: true}
	}
	var joined graph.Interval
	sawAny := false
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		expr := children[0]
		var iv graph.Interval
		switch expr.Kind() {
		case "number_literal":
			var v int64
			if _, err := fmt.Sscanf(expr.Text(), "%d", &v); err == nil {
				iv = graph.Interval{Lo: v, Hi: v}
			} else {
				iv = graph.Interval{Top: true}
			}
		case "identifier":
			if r := flow.at(expr.Text(), ret.StartLine()); !r.isTop() {
				iv = graph.Interval{Lo: r.lo, Hi: r.hi}
			} else {
				iv = graph.Interval{Top: true}
			}
		case "call_expression":
			callee := expr.ChildByFieldName("function")
			if callee != nil && callee.Kind() == "identifier" {
				sub, _ := q.SummaryOf(ctx, callee.Text())
				iv = sub.Interval
			} else {
				iv = graph.Interval{Top: true}
			}
		default:
			iv = graph.Interval{Top: true}
		}
		if !sawAny {
			joined = iv
			sawAny = true
		} else {
			joined = joinIntervals(joined, iv)
		}
	}
	if !sawAny {
		return graph.Interval{Top: true}
	}
	return joined
}

// taintOf resolves the Taint dimension for funcName from the shared
// taintSummaryCache. A nil cache or a compute failure yields TriUnknown.
func (q *summaryQuerier) taintOf(ctx context.Context, funcName string) graph.Tri {
	if q.taintCache == nil {
		return graph.TriUnknown
	}
	ts, err := q.taintCache.get(ctx)
	if err != nil || ts == nil {
		return graph.TriUnknown
	}
	if ts.retTainted[funcName] {
		return graph.TriYes
	}
	return graph.TriNo
}

// capacityOf resolves the Capacity dimension for funcName: when the
// function's body returns the result of a `malloc(N)` / `calloc(N, ...)`
// call with a literal N, Capacity = N (the byte capacity of the returned
// buffer). Any other shape (non-literal size, no malloc return, multiple
// returns with different sizes) yields -1 (unknown).
func (q *summaryQuerier) capacityOf(ctx context.Context, funcName string) int64 {
	if q.store == nil || q.parser == nil {
		return -1
	}
	fn, err := q.store.GetFunctionByName(ctx, funcName)
	if err != nil || fn == nil {
		return -1
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return -1
	}
	body, _ := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return -1
	}
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		expr := children[0]
		if expr.Kind() != "call_expression" {
			continue
		}
		callee := expr.ChildByFieldName("function")
		if callee == nil || callee.Kind() != "identifier" {
			continue
		}
		name := callee.Text()
		if name != "malloc" && name != "calloc" {
			continue
		}
		args := expr.ChildByFieldName("arguments")
		if args == nil {
			continue
		}
		argList := args.NamedChildren()
		if len(argList) == 0 {
			continue
		}
		// malloc(N): capacity = N. calloc(N, M): capacity = N * M.
		if name == "malloc" {
			if v, ok := literalInt(argList[0]); ok {
				return v
			}
			continue
		}
		// calloc
		if len(argList) >= 2 {
			n, ok1 := literalInt(argList[0])
			m, ok2 := literalInt(argList[1])
			if ok1 && ok2 {
				return n * m
			}
		}
	}
	return -1
}

// literalInt parses a number_literal node's text as an int64. The second
// return value is false when the node is not a number_literal or the text
// is not a decimal integer.
func literalInt(n parser.Node) (int64, bool) {
	if n.Kind() != "number_literal" {
		return 0, false
	}
	var v int64
	if _, err := fmt.Sscanf(n.Text(), "%d", &v); err != nil {
		return 0, false
	}
	return v, true
}

// joinIntervals returns the hull of two intervals (the over-approximation
// covering both).
func joinIntervals(a, b graph.Interval) graph.Interval {
	if a.Top {
		return b
	}
	if b.Top {
		return a
	}
	lo, hi := a.Lo, a.Hi
	if b.Lo < lo {
		lo = b.Lo
	}
	if b.Hi > hi {
		hi = b.Hi
	}
	return graph.Interval{Lo: lo, Hi: hi}
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
