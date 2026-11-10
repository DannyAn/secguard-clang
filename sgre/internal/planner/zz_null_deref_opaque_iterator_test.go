//go:build !nosqlite

package planner

import "testing"

// Issue #253 P2-1: an opaque traversal macro (SLL_Scan / HPE_LIST_FOR_EACH_SAFE
// / LIST_FOR_EACH_ENTRY_RCU) assigns its iterator in the loop header by an
// out-of-tree definition. A must-null proof built on the pre-loop `p = NULL`
// must NOT auto-confirm the in-loop dereference: the macro call names the
// variable, so the candidate is demoted to suspected for AI judgment (macro
// context), never machine-confirmed — and never killed either, since the
// unconfigured-macro contract keeps a conservative finding. A plain
// `p = NULL; p->id` stays confirmed as the control.
func TestNullDeref_OpaqueIteratorMacroKillsDefiniteNull(t *testing.T) {
	src := `typedef struct node { int id; struct node *next; } node_t;

void real_definite_null(void)
{
    node_t *q = NULL;
    q->id = 1;
}

void walk(void *list)
{
    node_t *p = NULL;
    SLL_Scan(list, p, node_t *) {
        p->id = 0;
    }
}
`
	res := planNullDerefFullSrc(t, src)
	for _, c := range res.Candidates {
		if c.Target.Function == "walk" && c.Target.Variable == "p" && c.SuspicionLevel == "confirmed" {
			t.Errorf("walk: SLL_Scan reassigns the iterator in the loop header; the pre-loop p = NULL must not auto-confirm (hint=%v)", c.Hint)
		}
	}
	var control *EvidenceItem
	for i := range res.Candidates {
		if res.Candidates[i].Target.Function == "real_definite_null" {
			control = &res.Candidates[i]
		}
	}
	if control == nil {
		t.Fatalf("control must stay a candidate, got %v", candidateNames(res))
	}
	if control.SuspicionLevel != "confirmed" {
		t.Errorf("control: plain p = NULL; p->id must stay confirmed, got %q", control.SuspicionLevel)
	}
}
