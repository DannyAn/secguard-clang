//go:build !nosqlite

package planner

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/apikb"
)

func TestNullDeref_CallResultTiers(t *testing.T) {
	const nonNull = "__sgre_test_nonnull_call_result"
	apikb.RegisterNonNullReturning(nonNull)

	t.Run("direct non-null call result", func(t *testing.T) {
		src := `typedef struct { int x; } S;
extern S *` + nonNull + `(void);
void f(void) {
    ` + nonNull + `()->x = 1;
}
`
		if hasNullDerefCandidate(planNullDerefSrc(t, src), "f") {
			t.Fatalf("%s is declared non-null; dereference must be dropped", nonNull)
		}
	})

	t.Run("non-null through local wrapper", func(t *testing.T) {
		src := `typedef struct { int x; } S;
extern S *` + nonNull + `(void);
S *wrap(void) {
    return ` + nonNull + `();
}
void f(void) {
    S *p = wrap();
    p->x = 1;
}
`
		if hasNullDerefCandidate(planNullDerefSrc(t, src), "f") {
			t.Fatalf("wrapper returning %s must not propagate a nullable source", nonNull)
		}
	})

	t.Run("known nullable direct call result", func(t *testing.T) {
		src := `void f(void) {
    *strchr("abc", 'x') = 'X';
}
`
		res := planNullDerefSrc(t, src)
		if !hasNullDerefCandidate(res, "f") {
			t.Fatal("strchr direct dereference must remain a candidate")
		}
		for _, c := range res.Candidates {
			if c.Target.Function == "f" && c.SuspicionLevel != "confirmed" {
				t.Fatalf("strchr direct dereference should be auto-confirmed, got %q", c.SuspicionLevel)
			}
		}
	})

}
