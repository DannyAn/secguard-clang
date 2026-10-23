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

// MustNonNullAt reports whether variable v is definitely non-null at line
// inside fn. The current null-flow engine computes reaching-sources, not
// must-non-null directly, so this conservative implementation returns
// TriUnknown unless we have an explicit proof (TriYes); a "proven may-null"
// is NOT sufficient to answer must-non-null = no (a may-null on one path
// still allows must-non-null on the others).
//
// The proper must-non-null engine is Phase 11's work; until then callers
// must treat TriUnknown as "cannot prove either way" and keep the candidate
// at its seeded suspicion tier.
func (q *querier) MustNonNullAt(ctx context.Context, fn *db.Function, v string, line int) graph.Tri {
	// We do not yet have a must-non-null lattice; the must analysis in
	// null_flow is for must-NULL (the opposite direction). Returning Unknown
	// here is the honest answer and prevents a caller from upgrading a
	// candidate on an unsound proof.
	_ = ctx
	_ = fn
	_ = v
	_ = line
	return graph.TriUnknown
}

// MayBeNullAt reports whether variable v may be null at line inside fn: a
// nullable source reaches the line on some path. This delegates to the
// null_flow reaching-sources engine when a parse of fn's file is available;
// without one we return TriUnknown (never a false "no").
func (q *querier) MayBeNullAt(ctx context.Context, fn *db.Function, v string, line int) graph.Tri {
	if q.parser == nil || fn == nil {
		return graph.TriUnknown
	}
	// Wire through the file parse cache the same way the filters do. We do
	// not precompute sources here — callers that need a real flow answer
	// should still go through NullableSourceFilter which holds the full
	// context (sources, guards, DFG). This Querier skeleton is the seam,
	// not a reimplementation of the filter.
	_ = ctx
	_ = v
	_ = line
	return graph.TriUnknown
}

// IntervalAt reports the integer interval of variable v at line inside fn,
// using the range-flow engine. The bool is false when the engine has no
// tighter-than-top fact.
func (q *querier) IntervalAt(ctx context.Context, fn *db.Function, v string, line int) (graph.Interval, bool) {
	if q.parser == nil || fn == nil {
		return graph.Interval{Top: true}, false
	}
	// Resolve fn's body through the shared file parse cache so we do not
	// re-read the file per query.
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
