//go:build !nosqlite

package planner

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/graph"
)

// TestSummaryQuerierSeam pins the Phase-13 skeleton contract: the querier
// answers with the correct "unknown" placeholders (never fabricating a fact
// it does not have) so callers cannot accidentally rely on the dimensions
// the fixpoints have not yet been promoted for.
func TestSummaryQuerierSeam(t *testing.T) {
	q := NewSummaryQuerier(nil, nil, nil, nil)

	s, ok := q.SummaryOf(context.Background(), "foo")
	if !ok {
		t.Fatal("SummaryOf(foo) returned false, want true (unknown but resolvable)")
	}
	if s.Function != "foo" {
		t.Errorf("Summary.Function = %q, want foo", s.Function)
	}
	if s.Null != graph.TriUnknown {
		t.Errorf("Summary.Null = %v, want TriUnknown", s.Null)
	}
	if !s.Interval.Top {
		t.Errorf("Summary.Interval.Top = %v, want true", s.Interval.Top)
	}
	if s.Taint != graph.TriUnknown {
		t.Errorf("Summary.Taint = %v, want TriUnknown", s.Taint)
	}
	if s.Capacity != -1 {
		t.Errorf("Summary.Capacity = %d, want -1 (unknown)", s.Capacity)
	}

	// Empty name must fail cleanly.
	if _, ok := q.SummaryOf(context.Background(), ""); ok {
		t.Error("SummaryOf(\"\") unexpectedly returned true")
	}
}
