package parser

import "testing"

// The null-literal and null-guard predicates are now single-sourced in this
// package; these tests pin the C forms the detectors depend on.
func TestIsNullLiteral(t *testing.T) {
	src := `void f(void *p, int x) {
    p = NULL;
    p = nullptr;
    p = 0;
    p = (void *)0;
    p = (NULL);
    p = x;
    p = 1;
}`
	tree, err := NewParser().Parse([]byte(src), "null_literal.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []bool{true, true, true, true, true, false, false}
	assignments := tree.RootNode().FindAll("assignment_expression")
	if len(assignments) != len(want) {
		t.Fatalf("found %d assignments, want %d", len(assignments), len(want))
	}
	for i, a := range assignments {
		kids := a.NamedChildren()
		if len(kids) < 2 {
			t.Fatalf("assignment %d has %d named children", i, len(kids))
		}
		if got := IsNullLiteral(kids[len(kids)-1]); got != want[i] {
			t.Errorf("assignment %d: IsNullLiteral = %v, want %v", i, got, want[i])
		}
	}
}

func TestExprNullChecksParam(t *testing.T) {
	src := `void f(void *p) {
    if (p == NULL) {}
    if (!p) {}
    if (p->x == NULL) {}
}`
	tree, err := NewParser().Parse([]byte(src), "null_guard.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []bool{true, true, false}
	ifs := tree.RootNode().FindAll("if_statement")
	if len(ifs) != len(want) {
		t.Fatalf("found %d if statements, want %d", len(ifs), len(want))
	}
	for i, node := range ifs {
		cond := node.ChildByFieldName("condition")
		if cond == nil {
			t.Fatalf("if %d has no condition", i)
		}
		if got := ExprNullChecksParam(*cond, "p"); got != want[i] {
			t.Errorf("if %d: ExprNullChecksParam = %v, want %v", i, got, want[i])
		}
	}
}
