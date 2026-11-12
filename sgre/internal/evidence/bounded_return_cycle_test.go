package evidence

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Issue #253 P0-1: boundedByParam followed the identifier -> single-assignment
// edge with no cycle guard and no depth cap. A cyclic assignment pair
// (`a = b; b = a;`) recursed forever and a several-thousand-deep generated
// chain exhausted the 1 GB goroutine stack — an unrecoverable `fatal error:
// stack overflow` that killed the whole scan inside the integer_overflow
// detector. Both shapes must now terminate promptly as "not provably bounded".
func TestBoundedByParamAssignmentCycleTerminates(t *testing.T) {
	src := `unsigned f(char *buf, unsigned size) {
    unsigned a;
    unsigned b;
    a = b;
    b = a;
    return a;
}
`
	assertBoundedByParamTerminates(t, src)
}

func TestBoundedByParamDeepChainTerminates(t *testing.T) {
	var b strings.Builder
	b.WriteString("unsigned f(char *buf, unsigned size) {\n")
	const depth = 10000
	for i := 0; i <= depth; i++ {
		fmt.Fprintf(&b, "    unsigned v%d;\n", i)
	}
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "    v%d = v%d;\n", i, i+1)
	}
	b.WriteString("    return v0;\n}\n")
	assertBoundedByParamTerminates(t, b.String())
}

// TestBoundedByParamNestedTernaryTerminates pins the field-report crash shape
// (issue #264 #1): multi-level nested ternaries feeding a length/offset
// computation. The conditional_expression branch must stay non-recursive — a
// min-clamp probe that reads only the two branch tips — so arbitrary nesting
// depth terminates as "not provably bounded" instead of exhausting the
// goroutine stack.
func TestBoundedByParamNestedTernaryTerminates(t *testing.T) {
	var b strings.Builder
	b.WriteString("unsigned f(char *buf, unsigned size, unsigned a, unsigned c) {\n")
	const depth = 10000
	b.WriteString("    return ")
	for i := 0; i < depth; i++ {
		b.WriteString("c ? (")
	}
	b.WriteString("a + 1")
	for i := 0; i < depth; i++ {
		b.WriteString(") : (a - 1)")
	}
	b.WriteString(";\n}\n")
	assertBoundedByParamTerminates(t, b.String())
}

func assertBoundedByParamTerminates(t *testing.T, src string) {
	t.Helper()
	pp := parser.NewParser()
	tree, err := pp.Parse([]byte(src), "cycle.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := tree.RootNode()
	defs := root.FindAll("function_definition")
	if len(defs) == 0 {
		t.Fatal("no function_definition parsed")
	}
	bodies := functionBodyMap(defs)
	f := &db.Function{Name: "f", StartLine: defs[0].StartLine()}
	assigned := singleAssignments(f, root.FindAll("init_declarator"), root.FindAll("assignment_expression"))
	body := bodies[defs[0].StartLine()]
	returns := body.FindAll("return_statement")
	if len(returns) == 0 {
		t.Fatal("no return_statement parsed")
	}
	expr := returnExprNode(returns[0])
	if expr == nil {
		t.Fatal("return has no expression")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		boundedByParam(*expr, []string{"buf", "size"}, assigned, boundedReturnSummary{})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("boundedByParam did not terminate (assignment cycle / unbounded recursion)")
	}
}
