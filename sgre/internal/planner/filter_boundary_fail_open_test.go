package planner

import (
	"context"
	"testing"
)

func boundaryCandidate(tier string) Candidate {
	return Candidate{FunctionName: "f", VariableName: "p", Line: 10, NullOriginTier: tier}
}

func TestBoundaryFailOpenFilterExternalMode(t *testing.T) {
	f := NewBoundaryFailOpenFilter(true, "external")
	kept, dropped, err := f.Apply(context.Background(), []Candidate{
		boundaryCandidate("opaque-origin"),
		boundaryCandidate("external-unknown"),
		boundaryCandidate("callback-entry"),
		boundaryCandidate("caller-arg"),
		boundaryCandidate("assumed-return"),
		boundaryCandidate("array-buffer"),
		boundaryCandidate("cfg-proof"),
		boundaryCandidate("malloc-fail"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 3 || len(kept) != 5 {
		t.Fatalf("external mode kept=%d dropped=%d, want 5/3", len(kept), len(dropped))
	}
	for _, d := range dropped {
		if d.Filter != "boundary_fail_open" || d.Reason == "" {
			t.Errorf("dropped entry lacks provenance: %+v", d)
		}
	}
}

// TestBoundaryFailOpenFilterCallerArgRoot pins the "unguarded external entry"
// split: a caller-arg candidate rooted at an unguarded external entry (no
// concrete NULL witness) is the same fail-open assumption as opaque-origin, so
// it is dismissed in "external" mode; a forwarding hop keeps a concrete caller
// and stays for the AI unless "all" drops it.
func TestBoundaryFailOpenFilterCallerArgRoot(t *testing.T) {
	root := boundaryCandidate("caller-arg")
	root.ChainKind = "root"
	hop := boundaryCandidate("caller-arg")
	hop.ChainKind = "hop"

	kept, dropped, err := NewBoundaryFailOpenFilter(true, "external").Apply(context.Background(), []Candidate{root, hop})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || len(kept) != 1 {
		t.Fatalf("external mode root/hop: kept=%d dropped=%d, want 1/1", len(kept), len(dropped))
	}
	if dropped[0].Reason == "" || kept[0].ChainKind != "hop" {
		t.Errorf("root must be dismissed, hop kept: dropped=%+v kept=%+v", dropped, kept)
	}
}

func TestBoundaryFailOpenFilterAllMode(t *testing.T) {
	f := NewBoundaryFailOpenFilter(true, "all")
	kept, dropped, err := f.Apply(context.Background(), []Candidate{
		boundaryCandidate("caller-arg"),
		boundaryCandidate("assumed-return"),
		boundaryCandidate("array-buffer"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 2 || len(kept) != 1 {
		t.Fatalf("all mode kept=%d dropped=%d, want 1/2", len(kept), len(dropped))
	}
}

func TestBoundaryFailOpenFilterKeepsInTreeChain(t *testing.T) {
	f := NewBoundaryFailOpenFilter(true, "all")
	c := boundaryCandidate("opaque-origin")
	c.Callers = []string{"caller"}
	kept, dropped, err := f.Apply(context.Background(), []Candidate{c})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || len(dropped) != 0 {
		t.Fatalf("in-tree caller must be kept: kept=%d dropped=%d", len(kept), len(dropped))
	}
}

func TestBoundaryFailOpenFilterOff(t *testing.T) {
	for _, f := range []*BoundaryFailOpenFilter{
		NewBoundaryFailOpenFilter(false, "all"),
		NewBoundaryFailOpenFilter(true, "off"),
	} {
		kept, dropped, err := f.Apply(context.Background(), []Candidate{
			boundaryCandidate("opaque-origin"),
			boundaryCandidate("external-unknown"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(dropped) != 0 || len(kept) != 2 {
			t.Fatalf("off must keep everything: kept=%d dropped=%d", len(kept), len(dropped))
		}
	}
}
