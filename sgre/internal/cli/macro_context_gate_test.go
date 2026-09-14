package cli

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

// splitBySuspicion must NOT auto-confirm a pipeline-proved candidate whose
// context involves a function-like macro: macro semantics are exactly where the
// deterministic pipeline mis-models control flow, so such a candidate goes to AI
// review even when its suspicion_level reads "confirmed".
func TestSplitBySuspicion_MacroContextRoutesToAI(t *testing.T) {
	candidates := []planner.EvidenceItem{
		{SuspicionLevel: "confirmed", MacroContext: true},  // guard macro missed → AI
		{SuspicionLevel: "confirmed", MacroContext: false}, // proved, no macro → auto-confirm
		{SuspicionLevel: "suspected", MacroContext: false}, // heuristic → AI
	}

	confirmed, needsReview := splitBySuspicion(candidates)
	if len(confirmed) != 1 {
		t.Fatalf("confirmed = %d, want 1 (only the non-macro confirmed candidate)", len(confirmed))
	}
	if confirmed[0].MacroContext {
		t.Errorf("a macro-context candidate must never be auto-confirmed")
	}
	if len(needsReview) != 2 {
		t.Fatalf("needsReview = %d, want 2 (macro-context confirmed + suspected)", len(needsReview))
	}
}
