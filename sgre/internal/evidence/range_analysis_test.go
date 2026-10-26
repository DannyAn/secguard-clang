package evidence

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestAnalyzeBounds_ElseBranchReassignKillsNonZero pins the P1 fix: the
// reassignment guard `if (x == 0) x = 1;` establishes x non-zero on the
// fall-through only when the else branch does NOT reassign x to a possibly-zero
// value. `if (x==0) x=1; else x=0;` must NOT establish the fact.
func TestAnalyzeBounds_ElseBranchReassignKillsNonZero(t *testing.T) {
	p := parser.NewParser()
	defer p.CloseAll()

	src := `void f(int x) {
    if (x == 0) x = 1; else x = 0;
    use(x);
}`
	tree, err := p.Parse([]byte(src), "else.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := tree.RootNode()
	bounds := AnalyzeBounds(root.FindAll("if_statement"), root.FindAll("assignment_expression"))
	useLine := 0
	for _, c := range root.FindAll("call_expression") {
		if extractCallName(c) == "use" {
			useLine = c.StartLine()
		}
	}
	if useLine == 0 {
		t.Fatal("use call not found")
	}
	if bounds.NonZeroAt("x", useLine) {
		t.Errorf("x must NOT be established non-zero after `if (x==0) x=1; else x=0;` (else reassigns zero)")
	}
}

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

// TestAnalyzeBounds_OrExitGuard pins the De Morgan expansion for a disjunctive
// EARLY-EXIT guard. Production (NAT) confirmed two divide-by-zero false
// positives whose zero guard sat in the same ±8-line window:
//
//	if (port_width == 0 || port_index >= ps->port_num) { return INVALID; }
//	if ((num == 0) || (size == 0)) { *start = 1; *end = 1; return; }
//
// Falling through either guard means EVERY disjunct is false, so each
// `x == 0` disjunct establishes `x != 0` on the surviving path.
func TestAnalyzeBounds_OrExitGuard(t *testing.T) {
	p := parser.NewParser()
	defer p.CloseAll()

	facts := func(name, src string, useLine int) *RangeFacts {
		t.Helper()
		tree, err := p.Parse([]byte(src), name)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		root := tree.RootNode()
		return AnalyzeBounds(root.FindAll("if_statement"), root.FindAll("assignment_expression"))
	}

	t.Run("field and bound disjunct", func(t *testing.T) {
		src := `int f(struct ps *p, unsigned int idx) {
    unsigned int w = p->width;
    if (w == 0 || idx >= p->num) {
        return -1;
    }
    return 10 / w;
}`
		b := facts("or1.c", src, 6)
		if !b.NonZeroAt("w", 6) {
			t.Errorf("w must be non-zero after `if (w == 0 || idx >= num) return;`")
		}
		if b.NonZeroAt("idx", 6) {
			t.Errorf("idx must NOT be proven non-zero (its disjunct is a bound, not a zero test)")
		}
	})

	t.Run("parenthesized or with body statements", func(t *testing.T) {
		src := `void f(unsigned int num, unsigned int size) {
    if ((num == 0) || (size == 0)) {
        use(num);
        return;
    }
    use(num / size);
}`
		b := facts("or2.c", src, 6)
		if !b.NonZeroAt("size", 6) {
			t.Errorf("size must be non-zero after `if ((num == 0) || (size == 0)) return;`")
		}
	})

	// Controls: the expansion must not leak into shapes where the negation does
	// not prove non-zero.
	t.Run("and guard does not prove non-zero", func(t *testing.T) {
		src := `int f(int a, int b) {
    if (a == 0 && b == 0) {
        return -1;
    }
    return 10 / a;
}`
		b := facts("and.c", src, 5)
		if b.NonZeroAt("a", 5) {
			t.Errorf("`if (a == 0 && b == 0) return;` does not prove a != 0")
		}
	})
	t.Run("positive or guard does not prove non-zero", func(t *testing.T) {
		src := `int f(int a, int b) {
    if (a == 0 || b == 0) {
        use(a);
    }
    return 10 / a;
}`
		b := facts("pos.c", src, 5)
		if b.NonZeroAt("a", 5) {
			t.Errorf("a positive `if (a == 0 || b == 0) { ... }` branch proves nothing on the fall-through")
		}
	})
}
