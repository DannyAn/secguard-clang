package evidence

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestAnalyzeBounds_UpperBoundReassignKill locks in that a whole-variable
// reassignment invalidates the upper bound a guard established: `if (n <= 16)`
// bounds n at 16, but a later `n = 100` inside the body means memcpy(dst, src,
// n) is no longer provably in-bounds, so UpperBoundAt must return 0 (no bound).
func TestAnalyzeBounds_UpperBoundReassignKill(t *testing.T) {
	p := parser.NewParser()
	defer p.CloseAll()

	parse := func(name, src string) *RangeFacts {
		t.Helper()
		tree, err := p.Parse([]byte(src), name)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		root := tree.RootNode()
		return AnalyzeBounds(root.FindAll("if_statement"), root.FindAll("assignment_expression"))
	}
	memcpyLine := func(name, src string) int {
		t.Helper()
		tree, err := p.Parse([]byte(src), name)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, c := range tree.RootNode().FindAll("call_expression") {
			if extractCallName(c) == "memcpy" {
				return c.StartLine()
			}
		}
		t.Fatalf("%s: memcpy not found", name)
		return 0
	}

	const noReassign = `#include <string.h>
void f(char *src, int n) {
    char dst[16];
    if (n <= 16) {
        memcpy(dst, src, n);
    }
}`
	if got := parse("no_reassign.c", noReassign).UpperBoundAt("n", memcpyLine("no_reassign.c", noReassign)); got != 16 {
		t.Errorf("UpperBoundAt without reassignment: got %d, want 16", got)
	}

	const reassigned = `#include <string.h>
void f(char *src, int n) {
    char dst[16];
    if (n <= 16) {
        n = 100;
        memcpy(dst, src, n);
    }
}`
	if got := parse("reassigned.c", reassigned).UpperBoundAt("n", memcpyLine("reassigned.c", reassigned)); got != 0 {
		t.Errorf("UpperBoundAt after n = 100: got %d, want 0", got)
	}
}
