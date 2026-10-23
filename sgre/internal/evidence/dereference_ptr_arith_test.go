package evidence

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// NE-01: pointer-arithmetic dereferences (`*(p+1)`, `*(p-i)`, `*((T*)p+off)`)
// must extract the base pointer as the dereferenced variable. Without a
// binary_expression case, derefOperandVar falls back to the raw text slice
// (`"(p+1)"`), which never matches the NULL_VALUE source key `p` — every
// pointer-arithmetic deref of a nullable pointer was a silent false negative.
func TestExplicitDerefVarPointerArithmetic(t *testing.T) {
	src := `typedef struct { int x; } T;
void f(T *p, int i, int off) {
    *(p+1) = 0;
    *(p-1) = 0;
    *(p+i) = 0;
    *((T*)p+off) = 0;
    *p = 0;
}
`
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var got []string
	for _, n := range tree.RootNode().FindAll("pointer_expression") {
		if v := explicitDerefVar(n); v != "" {
			got = append(got, v)
		}
	}
	// The four arithmetic forms plus the plain `*p` must all resolve to `p`.
	want := []string{"p", "p", "p", "p", "p"}
	if len(got) != len(want) {
		t.Fatalf("explicitDerefVar resolved %d derefs %v, want %d %v", len(got), got, len(want), want)
	}
	for i, v := range got {
		if v != want[i] {
			t.Errorf("deref[%d] variable = %q, want %q", i, v, want[i])
		}
	}
}

// End-to-end: a definite-null pointer dereferenced through pointer arithmetic
// must surface as a null-deref candidate (previously dropped: the deref key
// "(p+1)" never matched the NULL_VALUE source key "p").
func TestNullDeref_PointerArithmeticDefinite(t *testing.T) {
	result, _ := runFullPipeline(t, "tc116_ptr_arith_deref.c")
	for _, c := range result.Candidates {
		if c.Target.Function == "ptr_arith_definite" && c.Target.Variable == "p" {
			return
		}
	}
	t.Errorf("ptr_arith_definite `*(p+1)` null-deref was dropped (NE-01 regression); candidates: %+v", result.Candidates)
}
