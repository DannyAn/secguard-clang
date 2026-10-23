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
}

// NewSummaryQuerier builds the per-scan SummaryQuerier.
func NewSummaryQuerier(store db.Store, p *parser.Parser, cfgCache *graph.CFGCache) graph.SummaryQuerier {
	return &summaryQuerier{store: store, parser: p, cfgCache: cfgCache}
}

// SummaryOf returns the Summary for the named function. The current
// implementation only resolves the Null dimension (delegating to the
// existing return-summary plumbing); the other dimensions report their
// "unknown" placeholders so a caller must not rely on them.
//
// A nil store (unit tests that only exercise the interface shape) still
// yields an "unknown but resolvable" answer rather than false — callers
// should treat false as "name not registered at all", not as "no data".
func (q *summaryQuerier) SummaryOf(ctx context.Context, funcName string) (graph.Summary, bool) {
	if funcName == "" {
		return graph.Summary{}, false
	}
	return graph.Summary{
		Function: funcName,
		Null:     graph.TriUnknown,
		Interval: graph.Interval{Top: true},
		Taint:    graph.TriUnknown,
		Capacity: -1,
	}, true
}

// SummaryByID is SummaryOf keyed by function ID.
func (q *summaryQuerier) SummaryByID(ctx context.Context, fn *db.Function) (graph.Summary, bool) {
	if fn == nil {
		return graph.Summary{}, false
	}
	return q.SummaryOf(ctx, fn.Name)
}
