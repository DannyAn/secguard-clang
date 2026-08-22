//go:build !nosqlite

package planner

import (
	"testing"
)

// TestFieldSensitivity_CopyFromField pins the field-sensitive copy: `q = s->next`
// must propagate the nullness of location s->next (not the whole struct s) into
// q. A null fact on a DIFFERENT field must not reach q.
func TestFieldSensitivity_CopyFromField(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct Node { int value; struct Node *next; struct Node *other; } Node;

int tp_copy_null_field(Node *s) {
    s->next = NULL;
    Node *q = s->next;
    return q->value;
}

int fp_copy_nonnull_field(Node *s) {
    s->next = NULL;
    Node *q = s->other;
    return q->value;
}
`
	result := runNullPlan(t, src)
	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}
	if !kept["tp_copy_null_field"] {
		t.Errorf("tp_copy_null_field (copy from a null field) should be kept, got %v", candidateNames(result))
	}
	if kept["fp_copy_nonnull_field"] {
		t.Errorf("fp_copy_nonnull_field (copy from a DIFFERENT, non-null field) should NOT be kept, got %v", candidateNames(result))
	}
}

// TestFieldSensitivity_ReassignInvalidatesFields pins field invalidation: after
// `p = <new object>`, the stale `p->f` null fact must be cleared, because p now
// points to a different object whose field f is unrelated.
func TestFieldSensitivity_ReassignInvalidatesFields(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct Node { int value; struct Node *next; } Node;

int fp_field_reassigned_base(Node *s) {
    Node other;
    s->next = NULL;
    s = &other;
    Node *q = s->next;
    return q->value;
}

int tp_field_null_persists(Node *s) {
    s->next = NULL;
    Node *q = s->next;
    return q->value;
}
`
	result := runNullPlan(t, src)
	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}
	if kept["fp_field_reassigned_base"] {
		t.Errorf("fp_field_reassigned_base (field null then base reassigned) should NOT be kept, got %v", candidateNames(result))
	}
	if !kept["tp_field_null_persists"] {
		t.Errorf("tp_field_null_persists (field null then same field deref) should be kept, got %v", candidateNames(result))
	}
}
