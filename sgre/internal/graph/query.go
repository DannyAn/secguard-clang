package graph

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// Tri is a three-state verdict used by semantic queries: a fact can be proven
// true, proven false, or unknown (in which case the caller must not assume
// either direction — typically it should keep the candidate suspected for
// the AI classifier rather than auto-confirm or auto-dismiss).
type Tri int

const (
	TriUnknown Tri = iota
	TriYes
	TriNo
)

// String renders t for logs and diagnostics.
func (t Tri) String() string {
	switch t {
	case TriYes:
		return "yes"
	case TriNo:
		return "no"
	default:
		return "unknown"
	}
}

// Querier is the semantic-query facade the detector and planner stages use to
// ask path-sensitive questions about a function ("is this variable null at
// line N?", "what is the interval of this expression at line N?") without
// rebuilding flow analyses per consumer. It is the seam that turns the
// pipeline's per-filter flow engines (null_flow / range_flow / alias) into a
// shared service.
//
// The interface is declared here in the graph package so evidence / cli can
// consume it without importing planner; the concrete implementation lives in
// planner (which owns the flow engines) and is injected at pipeline start.
type Querier interface {
	// MustNonNullAt reports whether variable v is definitely non-null at the
	// given line inside fn (a guard or assignment proves it on every path).
	MustNonNullAt(ctx context.Context, fn *db.Function, v string, line int) Tri
	// MayBeNullAt reports whether variable v may be null at the given line
	// inside fn (a nullable source reaches the line on some path).
	MayBeNullAt(ctx context.Context, fn *db.Function, v string, line int) Tri
	// IntervalAt reports the integer interval of variable v at the given line
	// inside fn. The boolean is false when the engine cannot produce a
	// tighter-than-top fact.
	IntervalAt(ctx context.Context, fn *db.Function, v string, line int) (Interval, bool)
	// TypeOf reports the C type of the named variable inside fn, resolved
	// from the variable's declaration. The boolean is false when the type
	// cannot be determined (a typedef needing repofacts, a field access, an
	// expression shape the skeleton does not yet handle).
	TypeOf(ctx context.Context, fn *db.Function, v string) (Type, bool)
}

// Interval is the integer interval used by the range engine. It is declared
// here (rather than importing planner) so graph.Querier can expose it.
type Interval struct {
	Lo  int64
	Hi  int64
	Top bool // when true, Lo/Hi are meaningless (the unbounded interval)
}
