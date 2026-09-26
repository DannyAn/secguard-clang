//go:build !nosqlite

package planner

import "testing"

// UF-02/07: free(p); q = p; free(q) is a double-free of p's block — the detector
// now aggregates both frees under the terminal alias base.
func TestDoubleFreeReview_Alias(t *testing.T) {
	src := `#include <stdlib.h>
int df_alias(void) {
    int *p = malloc(8);
    int *q = p;
    free(p);
    free(q);
    return 0;
}
`
	got := planType(t, src, "double-free")
	if got["df_alias"].Target.Function == "" {
		t.Errorf("df_alias: free(p); q=p; free(q) must be a double-free, got %v", keysOf(got))
	}
}

// UF-04/08: p = q; free(q); use(p) — freeing the base also dangles the alias.
func TestUseAfterFreeReview_ReverseAlias(t *testing.T) {
	src := `#include <stdlib.h>
int uaf_reverse(void) {
    int *p = malloc(8);
    int *q = p;
    free(q);
    return *p;
}
`
	got := planType(t, src, "use-after-free")
	if got["uaf_reverse"].Target.Function == "" {
		t.Errorf("uaf_reverse: p=q; free(q); *p must be a use-after-free, got %v", keysOf(got))
	}
}

// UF-05: use identification covers return p, `x = p`, and subscript `p[i]`.
func TestUseAfterFreeReview_UseShapes(t *testing.T) {
	src := `#include <stdlib.h>
int uaf_return(void) {
    int *p = malloc(8);
    free(p);
    return *p;
}
int uaf_rhs(void) {
    int *p = malloc(8);
    int *q;
    free(p);
    q = p;
    return q != 0;
}
int uaf_subscript(void) {
    int *p = malloc(8 * sizeof(int));
    free(p);
    return p[0];
}
`
	got := planType(t, src, "use-after-free")
	for _, fn := range []string{"uaf_return", "uaf_rhs", "uaf_subscript"} {
		if got[fn].Target.Function == "" {
			t.Errorf("%s: freed pointer used again must be flagged, got %v", fn, keysOf(got))
		}
	}
}

// UF-01/06: a loop-carried use-after-free (use before free in source order, but
// free reaches the next iteration's use via the back-edge) is now emitted.
func TestUseAfterFreeReview_LoopCarried(t *testing.T) {
	src := `#include <stdlib.h>
int loop_carried(void) {
    int *p = malloc(8);
    for (int i = 0; i < 3; i++) {
        use(p);
        free(p);
    }
    return 0;
}
`
	got := planType(t, src, "use-after-free")
	if got["loop_carried"].Target.Function == "" {
		t.Errorf("loop_carried: use(p) after the previous iteration's free(p) must be flagged, got %v", keysOf(got))
	}
}
