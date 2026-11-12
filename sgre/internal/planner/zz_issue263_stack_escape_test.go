//go:build !nosqlite

package planner

import "testing"

// TestStackEscape_Issue263_TypedefPointerViews pins the issue #263 P0-3.1
// fix: a pointer-typedef (or cast) rename of a parameter is not a local
// object, so `&q->field` on the renamed view must not be reported at all;
// an OPAQUE typedef base (the detector cannot prove whether the address
// lands in this frame or the pointee) is downgraded to a suspected lead —
// never auto-confirmed — while genuine in-frame escapes keep the confirmed
// tier.
func TestStackEscape_Issue263_TypedefPointerViews(t *testing.T) {
	res := planNewType(t, "zz_issue263_stack_escape_typedef.c", "stack-address-escape")
	byFunc := map[string]*EvidenceItem{}
	for i := range res.Candidates {
		byFunc[res.Candidates[i].Target.Function] = &res.Candidates[i]
	}

	for _, fn := range []string{"typedef_ptr_view", "cast_view"} {
		if c, ok := byFunc[fn]; ok {
			t.Errorf("%s: want no candidate (renamed pointer view of a parameter), got %s/%s at line %d",
				fn, c.Target.Variable, c.SuspicionLevel, c.Target.Line)
		}
	}

	c := byFunc["opaque_struct_escape"]
	if c == nil {
		t.Fatal("opaque_struct_escape: want a downgraded candidate")
	}
	if c.SuspicionLevel != "suspected" {
		t.Errorf("opaque base: suspicion = %q, want suspected (auto-confirm is the issue #263 defect)", c.SuspicionLevel)
	}
	if c.Category != "return_stack_address_opaque" {
		t.Errorf("opaque base: category = %q, want return_stack_address_opaque", c.Category)
	}
	if c.BaseKind != "opaque" {
		t.Errorf("opaque base: base_kind = %q, want opaque", c.BaseKind)
	}

	for _, fn := range []string{"real_local_escape", "plain_addr_escape"} {
		ctrl := byFunc[fn]
		if ctrl == nil {
			t.Errorf("%s: want a confirmed control candidate", fn)
			continue
		}
		if ctrl.SuspicionLevel != "confirmed" {
			t.Errorf("%s: suspicion = %q, want confirmed (control)", fn, ctrl.SuspicionLevel)
		}
	}
}
