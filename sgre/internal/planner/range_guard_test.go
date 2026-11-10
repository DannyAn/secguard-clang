package planner

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func analyzeRangesSrc(t *testing.T, src string, endLine int) *rangeFlow {
	t.Helper()
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "guard.c")
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
	f := analyzeRanges(&db.Function{Name: "f", EndLine: endLine}, *body)
	if f == nil {
		t.Fatal("analyzeRanges returned nil")
	}
	return f
}

// Issue #253 P2-1: `if (i >= 16) return;` constrains the fall-through edge to
// i <= 15, so the later arr[i] must NOT be auto-confirmable as OOB (its index
// lower bound stays below the capacity). The worklist's monotone join keeps a
// conservative over-approximation rather than an exact unreachable/top, and
// that is sufficient: confirmed requires iv.lo >= size, which no longer holds.
func TestRangeGuardUnreachableFallThrough(t *testing.T) {
	src := `void f(void) {
    int i = 16;
    int arr[16];
    if (i >= 16) { return; }
    arr[i] = 1;
}
`
	f := analyzeRangesSrc(t, src, 6)
	iv := f.at("i", 5)
	if iv.lo >= 16 {
		t.Errorf("guarded fall-through must not keep an OOB-confirmable interval (lo >= 16), got %v", iv)
	}
}

// Control: without the guard, the same constant assignment reaches the access.
func TestRangeGuardNoGuardKeepsConstant(t *testing.T) {
	src := `void f(void) {
    int i = 16;
    int arr[16];
    arr[i] = 1;
}
`
	f := analyzeRangesSrc(t, src, 5)
	iv := f.at("i", 4)
	if iv.lo != 16 || iv.hi != 16 {
		t.Errorf("unguarded constant must stay [16,16], got %v", iv)
	}
}

// The false edge of `i >= 16` tightens an unknown parameter to i <= 15; the
// true edge tightens it to i >= 16.
func TestRangeGuardTightensParameter(t *testing.T) {
	src := `void f(int i) {
    if (i >= 16) { return; }
    sink(i);
}
int sink(int);
`
	f := analyzeRangesSrc(t, src, 5)
	iv := f.at("i", 3)
	if iv.hi != 15 {
		t.Errorf("fall-through of `i >= 16` must tighten hi to 15, got %v", iv)
	}
	iv = f.at("i", 2)
	if iv.lo != 16 {
		t.Errorf("true branch of `i >= 16` must tighten lo to 16, got %v", iv)
	}
}

// A `continue` guard inside a loop constrains the loop body the same way.
func TestRangeGuardContinueInLoop(t *testing.T) {
	src := `void f(int n) {
    int i = 0;
    for (i = 0; i < n; i++) {
        if (i >= 16) { continue; }
        sink(i);
    }
}
int sink(int);
`
	f := analyzeRangesSrc(t, src, 7)
	iv := f.at("i", 5)
	if iv.hi > 15 {
		t.Errorf("continue-guarded loop body must tighten hi to <= 15, got %v", iv)
	}
}
