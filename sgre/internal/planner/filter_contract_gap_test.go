package planner

import (
	"context"
	"testing"
)

// TestContractGapFilterEvidenceTiers pins the issue #200 implicit-contract
// policy: only a same-file sibling guard is strong enough for the AI. A
// self-guard-only row (no sibling reference) and a cross-file type-anchored
// sibling guard are both pre-dismissed into the ledger; the same-file sibling
// tier stays suspected.
func TestContractGapFilterEvidenceTiers(t *testing.T) {
	f := NewContractGapFilter(nil)
	kept, dropped, err := f.Apply(context.Background(), []Candidate{
		{FunctionName: "self_only", EvidenceKind: "self"},
		{FunctionName: "cross_file", EvidenceKind: "sibling-weak"},
		{FunctionName: "same_file", EvidenceKind: "sibling"},
		{FunctionName: "legacy", EvidenceKind: ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 2 || len(kept) != 2 {
		t.Fatalf("kept=%d dropped=%d, want 2/2", len(kept), len(dropped))
	}
	if kept[0].FunctionName != "same_file" || kept[1].FunctionName != "legacy" {
		t.Errorf("only sibling/legacy rows may be kept, got %v", kept)
	}
	for _, d := range dropped {
		if d.Filter != "contract_gap" || d.Reason == "" {
			t.Errorf("dismissed row lacks provenance: %+v", d)
		}
	}
}
