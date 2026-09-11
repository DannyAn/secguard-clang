package evidence

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// guardedVarOf parses `void g(void) { if (COND) { } }` and returns the variable
// extractGuardedVariable derives from that condition.
func guardedVarOf(t *testing.T, cond string) string {
	t.Helper()
	src := "void g(int x) { if (" + cond + ") { x = 1; } }\n"
	tree, err := parser.NewParser().Parse([]byte(src), "guard.c")
	if err != nil {
		t.Fatalf("parse %q: %v", cond, err)
	}
	var out string
	for _, ifNode := range tree.RootNode().FindAll("if_statement") {
		c := ifNode.ChildByFieldName("condition")
		if c == nil {
			continue
		}
		out = extractGuardedVariable(*c)
		break
	}
	return out
}

// TestExtractGuardedVariable_CompoundLvalue pins the guard name for a
// truth-check on a compound lvalue. The dereference and null-source detectors
// name the SAME source text (`packet_queue[i]`, `p->f`), and GuardFilter matches
// names exactly, so recording only the base identifier silently disabled the
// guard: `if (arr[i]) { free(arr[i]); }` kept leaking a candidate, and a guard on
// `p->f` could wrongly suppress a dereference of `p`.
func TestExtractGuardedVariable_CompoundLvalue(t *testing.T) {
	cases := []struct {
		cond string
		want string
	}{
		{"p", "p"},
		{"arr[i]", "arr[i]"},
		{"p->f", "p->f"},
		{"s.f", "s.f"},
		{"a[i]->f", "a[i]->f"},
		{"a[i][j]", "a[i][j]"},
		{"(*pp)", ""},               // a dereference is not an lvalue path
		{"p && q", "p"},             // boolean combination: first identifier fallback
		{"!p", "p"},                 // negation: first identifier fallback
		{"is_empty(p)", "is_empty"}, // call: first identifier fallback
		{"p != NULL", "p"},          // null comparison keeps its own path
		{"arr[i] != NULL", "arr[i]"},
	}
	for _, c := range cases {
		t.Run(c.cond, func(t *testing.T) {
			if got := guardedVarOf(t, c.cond); got != c.want {
				t.Errorf("extractGuardedVariable(%q) = %q, want %q", c.cond, got, c.want)
			}
		})
	}
}

// TestLvaluePath table-tests the path recogniser directly.
func TestLvaluePath(t *testing.T) {
	accept := []string{"p", "_x1", "a[i]", "a[i][j]", "p->f", "s.f", "a[i]->f->g", "p.f[0].g"}
	reject := []string{"", "p+q", "p && q", "*p", "f(x)", "p->", "p.", "1abc", "a[i", "p q"}
	for _, s := range accept {
		if got := lvaluePath(s); got != s {
			t.Errorf("lvaluePath(%q) = %q, want it accepted verbatim", s, got)
		}
	}
	for _, s := range reject {
		if got := lvaluePath(s); got != "" {
			t.Errorf("lvaluePath(%q) = %q, want rejection", s, got)
		}
	}
}
