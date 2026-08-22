package planner

import (
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestAnalyzeRanges_TerminatesOnLoop pins the widening fix: a loop counter
// (`for (i=0; i<n; i++)`) must not make the interval analysis widen one unit per
// back-edge pass forever. Without widening this test would hang until the Go test
// timeout; with it, analyzeRanges returns in well under the 5s guard.
func TestAnalyzeRanges_TerminatesOnLoop(t *testing.T) {
	src := `void f(int n) {
    int i = 0;
    for (i = 0; i < n; i++) {
        n = n + 1;
    }
    return;
}
`
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "t.c")
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
	fn := &db.Function{Name: "f", EndLine: 8}

	done := make(chan *rangeFlow, 1)
	go func() { done <- analyzeRanges(fn, *body) }()
	select {
	case f := <-done:
		if f == nil {
			t.Error("analyzeRanges returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("analyzeRanges did not terminate on a loop counter (widening regression)")
	}
}
