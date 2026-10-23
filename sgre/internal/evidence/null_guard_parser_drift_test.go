package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// NE-02/NE-11: the evidence layer's local guardedNonnullVars had drifted from
// parser.GuardedNonnullVars in two directions — it accepted `p != q` (both
// operands non-null) as a non-null guard, and it never unwrapped branch hints
// (`unlikely(p != NULL)`). The local copy is deleted; guard detection now
// shares parser.GuardedNonnullVars so the two layers can never drift again.
func TestNullGuard_NoFalseGuardFromNonNullComparison(t *testing.T) {
	store := runIndexAndDetect(t, "tc117_guard_parser_drift.c")
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "NULL_GUARD")
	if err != nil {
		t.Fatalf("list guard events: %v", err)
	}
	for _, e := range events {
		var props map[string]interface{}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("bad guard props %q: %v", e.Properties, err)
		}
		if props["variable"] == "w" {
			t.Errorf("`if (w != q)` must NOT emit a non-null guard for w (both operands are non-null); got event %+v", props)
		}
	}
}

func TestNullGuard_BranchHintWrappedGuardEmitted(t *testing.T) {
	store := runIndexAndDetect(t, "tc117_guard_parser_drift.c")
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "NULL_GUARD")
	if err != nil {
		t.Fatalf("list guard events: %v", err)
	}
	for _, e := range events {
		var props map[string]interface{}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("bad guard props %q: %v", e.Properties, err)
		}
		if props["variable"] == "p" {
			return // guard for `unlikely(p != NULL)` correctly emitted
		}
	}
	t.Errorf("`if (unlikely(p != NULL))` must emit a non-null guard for p (branch-hint unwrap); no p guard found in %d events", len(events))
}
