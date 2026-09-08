package cli

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestDistinctFindingLocations_CollapsesSameLocation(t *testing.T) {
	items := []planner.EvidenceItem{
		{Target: planner.TargetInfo{File: "a.c", Line: 10, Function: "f", Variable: "x"}},
		{Target: planner.TargetInfo{File: "a.c", Line: 10, Function: "f", Variable: "y"}},
		{Target: planner.TargetInfo{File: "a.c", Line: 11, Function: "f", Variable: "z"}},
		{Target: planner.TargetInfo{File: "b.c", Line: 10, Function: "g", Variable: "w"}},
	}
	if got := distinctFindingLocations(items); got != 3 {
		t.Errorf("distinctFindingLocations() = %d, want 3 (two vars on a.c:10 collapse into one)", got)
	}
}
