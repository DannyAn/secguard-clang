package evidence

import (
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Issue #267 reported a `fatal error: stack overflow` that killed the whole
// scan inside the integer_overflow detector. The confirmed infinite recursion
// (boundedByParam following the identifier -> single-assignment edge) is pinned
// by bounded_return_cycle_test.go. These tests pin the OTHER recursion surface
// of the same detector — the AST-structural walks nodeInfluenced and
// foldLiteralInt — against an arbitrarily deep expression (a 200k-deep binary
// chain and 200k-deep parentheses, the "long expression chain / deep macro
// expansion" shapes the production monorepo triggers). They are bounded by tree
// depth, so they must complete promptly instead of exhausting the goroutine
// stack.
func parseStressExpr(t *testing.T, expr string) parser.Node {
	t.Helper()
	pp := parser.NewParser()
	defer pp.CloseAll()
	tree, err := pp.Parse([]byte("unsigned f(unsigned x){ return "+expr+"; }"), "stress.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defs := tree.RootNode().FindAll("function_definition")
	if len(defs) == 0 {
		t.Fatal("no function_definition")
	}
	ret := defs[0].FindAll("return_statement")
	if len(ret) == 0 {
		t.Fatal("no return_statement")
	}
	n := returnExprNode(ret[0])
	if n == nil {
		t.Fatal("no return expression")
	}
	return *n
}

func TestDeepBinaryChainNoStackOverflow(t *testing.T) {
	const n = 200000
	var b strings.Builder
	b.WriteString("1")
	for i := 0; i < n; i++ {
		b.WriteString(" + 1")
	}
	expr := parseStressExpr(t, b.String())

	influenced := map[string]bool{"x": true}
	if nodeInfluenced(expr, influenced) {
		t.Fatal("a pure-literal chain must not be caller-influenced")
	}
	if _, ok := foldLiteralInt(expr); !ok {
		t.Fatal("a pure-literal chain must fold")
	}
}

func TestDeepParensNoStackOverflow(t *testing.T) {
	const n = 200000
	expr := parseStressExpr(t, strings.Repeat("(", n)+"x"+strings.Repeat(")", n))

	influenced := map[string]bool{"x": true}
	if !nodeInfluenced(expr, influenced) {
		t.Fatal("a parenthesized identifier is caller-influenced")
	}
}
