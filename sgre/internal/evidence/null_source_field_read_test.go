package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// ND-02: `p = p->next` is a self-referential field-read reassignment. The old
// value is gone; the new value is an open-world field read that can be NULL
// (the last hop of any linked-list/tree walk). Without a source of its own,
// the copy target `p->next` left the reassigned variable sourceless and the
// post-advance dereference was silently dropped.
func TestNullSource_FieldReadSelfAssign(t *testing.T) {
	store := runIndexAndDetect(t, "tc118_field_read_self_assign.c")
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list null-value events: %v", err)
	}
	for _, e := range events {
		var props map[string]interface{}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("bad props %q: %v", e.Properties, err)
		}
		if props["variable"] == "p" && props["origin"] == "field_read" {
			return
		}
	}
	t.Errorf("`p = p->next` must seed a field_read null source for p; got %d NULL_VALUE events with no such origin", len(events))
}

// NP-04 sibling: `T *r = *(T **)msg;` is a dereference-read assignment — the
// value read through msg is open-world nullable. It must seed a deref_read
// source for r.
func TestNullSource_DerefReadAssign(t *testing.T) {
	store := runIndexAndDetect(t, "tc119_deref_read_assign.c")
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list null-value events: %v", err)
	}
	for _, e := range events {
		var props map[string]interface{}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("bad props %q: %v", e.Properties, err)
		}
		if props["variable"] == "r" && props["origin"] == "deref_read" {
			return
		}
	}
	t.Errorf("`T *r = *(T **)msg;` must seed a deref_read null source for r; got %d NULL_VALUE events with no such origin", len(events))
}
