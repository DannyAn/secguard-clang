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

// NE-08: a user-defined `check_likely(x)` is NOT a branch hint — the
// *_likely/*_unlikely suffix match unwrapped ANY such call and treated its
// argument as the condition itself, manufacturing a phantom guard for `p`.
// Only the exact spellings (likely/unlikely/__builtin_expect) unwrap.
func TestGuardedNonnullVarsNonHintCallNotUnwrapped(t *testing.T) {
	src := `void f(void *p) {
    if (check_likely(p)) {
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
	if vars := GuardedNonnullVars(cond); len(vars) != 0 {
		t.Errorf("GuardedNonnullVars(check_likely(p)) = %v, want [] (a user call is not a branch hint and not a guard)", vars)
	}
}

// The exact hint spellings keep unwrapping (no regression).
func TestGuardedNonnullVarsExactHintUnwrapped(t *testing.T) {
	src := `void f(void *p) {
    if (unlikely(p != NULL)) {
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
	if vars := GuardedNonnullVars(cond); len(vars) != 1 || vars[0] != "p" {
		t.Errorf("GuardedNonnullVars(unlikely(p != NULL)) = %v, want [p]", vars)
	}
}

// Enterprise vendor hint macros are conventionally ALL-CAPS (Huawei VOS/HRP
// style). The ALL-CAPS suffix is unwrapped, so a guarded dereference is not
// falsely reported — while a lowercase user checker (check_likely) stays
// uncut, and a lowercase vendor spelling stays fail-open.
func TestGuardedNonnullVarsCapsVendorHintUnwrapped(t *testing.T) {
	for _, spelling := range []string{"VOS_LIKELY", "HRP_LIKELY", "OS_UNLIKELY", "DBM_LIKELY"} {
		src := "void f(void *p) {\n    if (" + spelling + "(p != NULL)) {\n    }\n}\n"
		tree, err := NewParser().Parse([]byte(src), "fixture.c")
		if err != nil {
			t.Fatalf("parse %s: %v", spelling, err)
		}
		var cond Node
		for _, ifs := range tree.RootNode().FindAll("if_statement") {
			if c := ifs.ChildByFieldName("condition"); c != nil {
				cond = *c
				break
			}
		}
		if vars := GuardedNonnullVars(cond); len(vars) != 1 || vars[0] != "p" {
			t.Errorf("GuardedNonnullVars(%s(p != NULL)) = %v, want [p] (ALL-CAPS vendor hint)", spelling, vars)
		}
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
