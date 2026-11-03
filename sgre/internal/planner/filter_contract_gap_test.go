package planner

import (
	"context"
	"testing"
)

// TestContractGapFilterEvidenceTiers pins the issue #200 + #206 implicit-contract
// policy: only a same-file sibling guard COMBINED with the function's own
// null-check (self-guard) is strong enough for the AI. A self-guard-only row (no
// sibling reference), a sibling-only row (no self-guard), and a cross-file
// type-anchored sibling guard are all pre-dismissed into the ledger; the
// sibling+self-guard residual and legacy rows stay suspected.
func TestContractGapFilterEvidenceTiers(t *testing.T) {
	f := NewContractGapFilter(nil)
	kept, dropped, err := f.Apply(context.Background(), []Candidate{
		{FunctionName: "self_only", EvidenceKind: "self"},
		{FunctionName: "cross_file", EvidenceKind: "sibling-weak"},
		{FunctionName: "sibling_only", EvidenceKind: "sibling"},
		{FunctionName: "sibling_and_self_guard", EvidenceKind: "sibling", GuardLine: 42},
		{FunctionName: "legacy", EvidenceKind: ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 3 || len(kept) != 2 {
		t.Fatalf("kept=%d dropped=%d, want 2/3", len(kept), len(dropped))
	}
	if kept[0].FunctionName != "sibling_and_self_guard" || kept[1].FunctionName != "legacy" {
		t.Errorf("only sibling+self-guard/legacy rows may be kept, got %v", kept)
	}
	for _, d := range dropped {
		if d.Filter != "contract_gap" || d.Reason == "" {
			t.Errorf("dismissed row lacks provenance: %+v", d)
		}
	}
}
