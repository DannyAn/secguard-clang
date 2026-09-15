package cli

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestDistinctFindingLocations_KeepsDistinctVariables(t *testing.T) {
	items := []planner.EvidenceItem{
		{Target: planner.TargetInfo{File: "a.c", Line: 10, Function: "f", Variable: "x"}},
		{Target: planner.TargetInfo{File: "a.c", Line: 10, Function: "f", Variable: "y"}},
		{Target: planner.TargetInfo{File: "a.c", Line: 11, Function: "f", Variable: "z"}},
		{Target: planner.TargetInfo{File: "b.c", Line: 10, Function: "g", Variable: "w"}},
	}
	// The finding UPSERT key now includes the variable, so x and y on a.c:10 are
	// two distinct findings (not collapsed), giving 4 total.
	if got := distinctFindingLocations(items); got != 4 {
		t.Errorf("distinctFindingLocations() = %d, want 4 (two vars on a.c:10 stay distinct)", got)
	}
}
