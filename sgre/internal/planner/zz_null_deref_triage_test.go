//go:build !nosqlite

package planner

import "testing"

func TestNullDeref_ShortCircuitGuardConverged(t *testing.T) {
	src := `typedef struct { int x; } S;
extern S *get_s(void);
void f(void) {
    S *p = get_s();
    if (p == NULL || p->x) {
        return;
    }
}
`
	if hasNullDerefCandidate(planNullDerefSrc(t, src), "f") {
		t.Fatal("p->x inside p == NULL || ... is short-circuit protected and must be converged")
	}
}
