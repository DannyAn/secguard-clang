package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// querier implements graph.Querier by reusing the pipeline's existing
// null-flow / range-flow engines. It is constructed once per scan (by the
// Planner) and shared across every consumer that needs a semantic answer,
// replacing the per-filter ad-hoc flow rebuilds the architecture review
// identified as the 8-12x duplicate work.
type querier struct {
	store    db.Store
	parser   *parser.Parser
	cfgCache *graph.CFGCache
}

// NewQuerier builds the per-scan Querier. cfgCache is shared with the
// Planner's CFG cache so flow engines hit the same per-function CFG builds.
func NewQuerier(store db.Store, p *parser.Parser, cfgCache *graph.CFGCache) graph.Querier {
	return &querier{store: store, parser: p, cfgCache: cfgCache}
}

// nullFlowFor builds fn's null-source reaching-sources flow via the shared
// engine. The sources come from the scan's NULL_VALUE events (the same
// source pool the NullableSourceFilter consumes), so the answer matches the
// pipeline's null-deref judgment, not a re-derivation. Returns nil when the
// body cannot be located (mock store, missing file, non-compound body) — the
// caller must then fall back to TriUnknown rather than guessing.
func (q *querier) nullFlowFor(ctx context.Context, fn *db.Function) *flowResult {
	if q.parser == nil || q.store == nil || fn == nil {
		return nil
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return nil
	}
	body, root := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return nil
	}
	models, err := buildNullModel(ctx, q.store)
	if err != nil {
		return nil
	}
	sources := nullSourcesFor(models, fn.ID)
	a := newFlowAnalyzer(q.store, q.parser, q.cfgCache)
	return a.analyzeFunction(ctx, fn, body, root, sources)
}

// MayBeNullAt reports whether variable v may be null at line inside fn: a
// nullable source reaches the line on some path. TriYes = a source provably
// reaches; TriUnknown = we cannot prove reach (either no source or the flow
// could not be built) — the caller must NOT treat TriUnknown as "provably
// non-null", only as "no evidence of nullability".
func (q *querier) MayBeNullAt(ctx context.Context, fn *db.Function, v string, line int) graph.Tri {
	flow := q.nullFlowFor(ctx, fn)
	if flow == nil {
		return graph.TriUnknown
	}
	if flow.reaching(v, line) {
		return graph.TriYes
	}
	return graph.TriUnknown
}

// MustNonNullAt reports whether variable v is definitely non-null at line
// inside fn. The conservative truth table:
//   - reachingDefinite(v, line) = true → v is PROVEN null → TriNo (must-non-null
//     is provably false)
//   - otherwise → TriUnknown (we have no must-non-null lattice yet; claiming
//     TriYes without one would let a caller upgrade a candidate on an unsound
//     proof)
//
// A future Phase adds the must-non-null lattice (a guard-dominated reaching
// analysis); until then this seam stays conservative.
func (q *querier) MustNonNullAt(ctx context.Context, fn *db.Function, v string, line int) graph.Tri {
	flow := q.nullFlowFor(ctx, fn)
	if flow == nil {
		return graph.TriUnknown
	}
	if flow.reachingDefinite(v, line) {
		return graph.TriNo
	}
	return graph.TriUnknown
}

// IntervalAt reports the integer interval of variable v at line inside fn,
// using the range-flow engine. The bool is false when the engine has no
// tighter-than-top fact.
func (q *querier) IntervalAt(ctx context.Context, fn *db.Function, v string, line int) (graph.Interval, bool) {
	if q.parser == nil || fn == nil {
		return graph.Interval{Top: true}, false
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return graph.Interval{Top: true}, false
	}
	body, _ := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return graph.Interval{Top: true}, false
	}
	flow := analyzeRangesWithCalls(q.cfgCache, fn, body, nil)
	if flow == nil {
		return graph.Interval{Top: true}, false
	}
	iv := flow.at(v, line)
	if iv.isTop() {
		return graph.Interval{Top: true}, false
	}
	return graph.Interval{Lo: iv.lo, Hi: iv.hi}, true
}
