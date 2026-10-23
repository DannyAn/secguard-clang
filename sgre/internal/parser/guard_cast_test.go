package parser

import "testing"

// ND-04: a cast guard `if ((struct T *)p != NULL)` must extract the guarded
// variable `p` — trimming the operand text `"(struct T *)p"` with
// strings.Trim(t,"()") produced the garbage name `"struct T *)p"`, so the
// guard never matched the dereferenced variable and the cast-guard-protected
// dereference was falsely flagged. Unwrap the cast structurally instead.
func TestGuardedNonnullVarsCastGuard(t *testing.T) {
	src := `typedef struct { int x; } T;
void f(T *p) {
    if ((struct T *)p != NULL) {
        p->x = 1;
    }
}
`
	tree, err := NewParser().Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var cond Node
	for _, ifs := range tree.RootNode().FindAll("if_statement") {
		if c := ifs.ChildByFieldName("condition"); c != nil {
			cond = *c
			break
		}
	}
	if cond.Kind() == "" {
		t.Fatal("no if condition found")
	}
	vars := GuardedNonnullVars(cond)
	if len(vars) != 1 || vars[0] != "p" {
		t.Errorf("GuardedNonnullVars((struct T *)p != NULL) = %v, want [p]", vars)
	}
}

// The plain form must keep working (no regression from the structural unwrap).
func TestGuardedNonnullVarsPlainGuard(t *testing.T) {
	src := `void f(void *p) {
    if (p != NULL) {
    }
}
`
	tree, err := NewParser().Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var cond Node
	for _, ifs := range tree.RootNode().FindAll("if_statement") {
		if c := ifs.ChildByFieldName("condition"); c != nil {
			cond = *c
			break
		}
	}
	vars := GuardedNonnullVars(cond)
	if len(vars) != 1 || vars[0] != "p" {
		t.Errorf("GuardedNonnullVars(p != NULL) = %v, want [p]", vars)
	}
}
