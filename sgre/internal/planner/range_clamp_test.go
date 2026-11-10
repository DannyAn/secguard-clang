package planner

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

func clampBody(t *testing.T, src string) parser.Node {
	t.Helper()
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "clamp.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	def := tree.RootNode().FindFirst("function_definition")
	if def == nil {
		t.Fatal("no function_definition")
	}
	body := def.FindFirst("compound_statement")
	if body == nil {
		t.Fatal("no compound_statement")
	}
	return *body
}

// Issue #253 P2-1: `if (pageSize == 0) { pageSize = DEFAULT; }` voids the
// caller-side literal-zero proof, so the clamp must be recognized (and only
// for the clamped parameter).
func TestParamZeroClamp(t *testing.T) {
	src := `void f(int pageSize) {
    if (pageSize == 0) { pageSize = 4096; }
    int x = 100 / pageSize;
    (void)x;
}
`
	if !paramZeroClamp(clampBody(t, src), "pageSize") {
		t.Error("if (pageSize == 0) { pageSize = 4096; } must be recognized as a zero clamp")
	}
}

func TestParamZeroClampMirroredCondition(t *testing.T) {
	src := `void f(int pageSize) {
    if (0 == pageSize) { pageSize = 4096; }
    int x = 100 / pageSize;
    (void)x;
}
`
	if !paramZeroClamp(clampBody(t, src), "pageSize") {
		t.Error("mirrored `0 == pageSize` must be recognized")
	}
}

func TestParamZeroClampAbsent(t *testing.T) {
	src := `void f(int pageSize) {
    int x = 100 / pageSize;
    (void)x;
}
`
	if paramZeroClamp(clampBody(t, src), "pageSize") {
		t.Error("no clamp present must return false (the auto-confirm still fires)")
	}
}

func TestParamZeroClampOtherVariable(t *testing.T) {
	src := `void f(int pageSize, int other) {
    if (other == 0) { other = 1; }
    int x = 100 / pageSize;
    (void)x;
}
`
	if paramZeroClamp(clampBody(t, src), "pageSize") {
		t.Error("a clamp of a DIFFERENT variable must not void the pageSize zero proof")
	}
}
