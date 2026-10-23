package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
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

// NE-10: classifyGuard tagged any condition containing "0" as NULL_CHECK —
// `flags == 0xFFFF` and `ret == err0` are not null checks. It now decides
// structurally (a ==/!= comparison against a null operand).
func TestClassifyGuardHexAndIdentZero(t *testing.T) {
	src := `void f(int flags, int ret, void *p) {
    if (flags == 0xFFFF) {}
    if (ret == err0) {}
    if (p == NULL) {}
    if (p != 0) {}
}
`
	pp := parser.NewParser()
	tree, err := pp.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var got []string
	for _, ifs := range tree.RootNode().FindAll("if_statement") {
		c := ifs.ChildByFieldName("condition")
		if c == nil {
			continue
		}
		got = append(got, classifyGuard(*c))
	}
	want := []string{"TRUTH_CHECK", "TRUTH_CHECK", "NULL_CHECK", "NULL_CHECK"}
	if len(got) != len(want) {
		t.Fatalf("classifyGuard returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("classifyGuard[%d] = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}
