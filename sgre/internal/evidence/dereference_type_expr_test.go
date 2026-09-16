package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// TestDeref_SizeofPseudoDerefTagged asserts sizeof/alignof dereferences are
// still emitted as DEREFERENCE events (so interprocedural null propagation keeps
// seeing them) but tagged is_type_expr=true, which the null-deref chain's
// sizeof_pseudo_deref filter uses to drop them.
func TestDeref_SizeofPseudoDerefTagged(t *testing.T) {
	store := runIndexAndDetect(t, "tc41_sizeof_pseudo_deref.c")
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "DEREFERENCE")
	if err != nil {
		t.Fatalf("list dereference events: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected sizeof derefs to still emit DEREFERENCE events, got 0")
	}
	for _, e := range events {
		var props map[string]string
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("bad dereference props %q: %v", e.Properties, err)
		}
		if props["is_type_expr"] != "true" {
			t.Errorf("dereference should be tagged is_type_expr=true, got props=%v", props)
		}
	}
}

// TestNullDeref_SizeofPseudoDerefNoFinding is the end-to-end guard: a nullable
// pointer (malloc result) whose only uses are sizeof type expressions must
// produce zero null-deref findings.
func TestNullDeref_SizeofPseudoDerefNoFinding(t *testing.T) {
	result, _ := runFullPipeline(t, "tc41_sizeof_pseudo_deref.c")
	assertNoFinding(t, result, "tc41_sizeof_pseudo_deref.c")
}

// TestNullDeref_NonNullableScopedToFunction pins the P5 fix: a local array `buf`
// in one function must not mark a same-named POINTER `buf` in a sibling function
// as non-nullable. The file-scoped-by-name version suppressed pointer_scope's
// malloc-unchecked null-deref (a silent false negative).
func TestNullDeref_NonNullableScopedToFunction(t *testing.T) {
	result, _ := runFullPipeline(t, "tc115_non_nullable_scope.c")
	for _, c := range result.Candidates {
		if c.Target.Function == "pointer_scope" {
			return // the malloc-unchecked deref survived
		}
	}
	t.Errorf("pointer_scope null-deref was suppressed by a same-named array in array_scope (P5 regression)")
}
