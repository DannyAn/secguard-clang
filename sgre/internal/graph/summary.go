package graph

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// Summary is a function's "return behavior" across several dimensions. Each
// dimension has its own fixpoint in the full implementation (Phase 13
// follow-up); the current skeleton only carries the shape.
//
// The dimensions answer the questions detectors actually ask:
//   - Null:       can the return value be NULL? (null-deref's retNullable)
//   - Interval:   the return-value's integer range (divide-by-zero's nonzero,
//     integer-overflow's "can this get big")
//   - Taint:      is the return value attacker-controlled? (injection)
//   - Capacity:   when the return is a buffer pointer, its byte/element
//     capacity (buffer-overflow's cross-function allocation)
type Summary struct {
	Function string
	// Null is TriYes / TriNo / TriUnknown for "return value can be NULL".
	Null Tri
	// Interval is the return-value's integer range. Top = unknown.
	Interval Interval
	// Taint is TriYes / TriNo / TriUnknown for "return value is
	// attacker-controlled".
	Taint Tri
	// Capacity is the byte/element capacity of the returned buffer; -1 =
	// unknown / not a buffer.
	Capacity int64
}

// SummaryQuerier is the cross-function summary facade. It complements the
// per-function Querier (which answers flow-sensitive questions inside one
// function) with cross-function return behavior. The detectors consume it
// so a call site `d = foo()` can use foo's summary instead of re-entering
// foo's body.
type SummaryQuerier interface {
	// SummaryOf returns the Summary for the named function, or false when
	// no summary is available (external / not-yet-computed / recursive).
	SummaryOf(ctx context.Context, funcName string) (Summary, bool)
	// SummaryByID is SummaryOf keyed by function ID instead of name.
	SummaryByID(ctx context.Context, fn *db.Function) (Summary, bool)
}
