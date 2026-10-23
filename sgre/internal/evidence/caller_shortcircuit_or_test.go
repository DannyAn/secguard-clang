package evidence

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// NE-03: a call on the RIGHT side of a `||` runs only when the LEFT side is
// FALSE — and the left's FALSE direction establishes `p` non-null when the
// left is `p == NULL`. callerShortCircuitGuards only walked `&&` ancestors
// and missed the `||` form entirely, so `p == NULL || callee(p)` classified
// the argument as an unguarded forward and flooded the openness chain.
func TestCallerShortCircuitGuardsOrBranch(t *testing.T) {
	src := `typedef struct { int x; } T;
int g(T *p);
void f(T *p) {
    if (p == NULL || g(p)) {
        return;
    }
}
`
	pp := parser.NewParser()
	tree, err := pp.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var call parser.Node
	for _, c := range tree.RootNode().FindAll("call_expression") {
		if c.Text() == "g(p)" {
			call = c
			break
		}
	}
	if call.Kind() == "" {
		t.Fatal("g(p) call not found")
	}
	if !callerShortCircuitGuards("p", call) {
		t.Errorf("`p == NULL || g(p)`: g(p) is guarded by the left operand's FALSE direction (p non-null); callerShortCircuitGuards returned false")
	}
}

// The && form must keep working (no regression from adding the || branch).
func TestCallerShortCircuitGuardsAndBranch(t *testing.T) {
	src := `typedef struct { int x; } T;
int g(T *p);
void f(T *p) {
    if (p != NULL && g(p)) {
        return;
    }
}
`
	pp := parser.NewParser()
	tree, err := pp.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var call parser.Node
	for _, c := range tree.RootNode().FindAll("call_expression") {
		if c.Text() == "g(p)" {
			call = c
			break
		}
	}
	if call.Kind() == "" {
		t.Fatal("g(p) call not found")
	}
	if !callerShortCircuitGuards("p", call) {
		t.Errorf("`p != NULL && g(p)`: g(p) is guarded by the left operand's TRUE direction; callerShortCircuitGuards returned false")
	}
}

// A call on the right of `||` whose LEFT does not null-check p stays
// unguarded: `errno == EAGAIN || g(p)` proves nothing about p.
func TestCallerShortCircuitGuardsOrBranchUnguardedLeft(t *testing.T) {
	src := `typedef struct { int x; } T;
int g(T *p);
void f(T *p, int errno_) {
    if (errno_ == 11 || g(p)) {
        return;
    }
}
`
	pp := parser.NewParser()
	tree, err := pp.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var call parser.Node
	for _, c := range tree.RootNode().FindAll("call_expression") {
		if c.Text() == "g(p)" {
			call = c
			break
		}
	}
	if call.Kind() == "" {
		t.Fatal("g(p) call not found")
	}
	if callerShortCircuitGuards("p", call) {
		t.Errorf("`errno_ == 11 || g(p)`: the left says nothing about p; callerShortCircuitGuards must return false")
	}
}
