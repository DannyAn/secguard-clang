package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestTargetsGuardDominatesSameBlockGuards pins the issue #216 guard model: a
// dereference inside the branch that proves the field non-null is guarded — the
// true branch of `if (p != NULL)` / `if (p)`, the else of `if (p == NULL)`, and
// a short-circuited `&&` operand. It also pins the fail-open edges: a guard whose
// scope does NOT contain the deref, a one-line guard followed by a same-line
// deref, and a guard invalidated by a reassignment must all stay unguarded.
func TestTargetsGuardDominatesSameBlockGuards(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		target string
		expr   string
		want   bool
	}{
		{
			name:   "if-body guard",
			src:    "void f(struct T *t) {\n    if (t->p != NULL) {\n        use(t->p->x); /*SINK*/\n    }\n}\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   true,
		},
		{
			name:   "truth-check body guard",
			src:    "void f(struct T *t) {\n    if (t->p) {\n        use(t->p->x); /*SINK*/\n    }\n}\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   true,
		},
		{
			name:   "else branch of null test",
			src:    "void f(struct T *t) {\n    if (t->p == NULL) {\n        log_it();\n    } else {\n        use(t->p->x); /*SINK*/\n    }\n}\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   true,
		},
		{
			name:   "short-circuit and operand",
			src:    "void f(struct T *t) {\n    if (t->p != NULL && t->p->x > 0) { /*SINK*/\n        return;\n    }\n}\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   true,
		},
		{
			name:   "one-line guarded body",
			src:    "void f(struct T *t) { if (t->p != NULL) { use(t->p->x); /*SINK*/ } }\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   true,
		},
		{
			name:   "guard does not dominate a later deref",
			src:    "void f(struct T *t) {\n    if (t->p != NULL) {\n        use(t->p);\n    }\n    use(t->p->x); /*SINK*/\n}\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   false,
		},
		{
			name:   "one-line guard then same-line deref fails open",
			src:    "void f(struct T *t) { if (t->p != NULL) { use(t->p); } use(t->p->x); /*SINK*/ }\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   false,
		},
		{
			name:   "reassignment inside the guarded body reopens the gap",
			src:    "void f(struct T *t) {\n    if (t->p != NULL) {\n        t->p = get_p();\n        use(t->p->x); /*SINK*/\n    }\n}\n",
			target: "t->p",
			expr:   "t->p->x",
			want:   false,
		},
	}
	p := parser.NewParser()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := strings.Index(tc.src, "/*SINK*/")
			if sink < 0 {
				t.Fatal("fixture has no /*SINK*/ marker")
			}
			line := 1 + strings.Count(tc.src[:sink], "\n")
			tree, err := p.Parse([]byte(tc.src), "blk.c")
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
			got := targetsGuardDominates(context.Background(), nil, nil, 0, *body, def.EndLine(), map[string]bool{tc.target: true}, line, tc.expr)
			if got != tc.want {
				t.Errorf("targetsGuardDominates(target=%s, line=%d, expr=%s) = %v, want %v",
					tc.target, line, tc.expr, got, tc.want)
			}
		})
	}
}

// TestContractGapFilterEvidenceTiers pins the issue #200 + #206 implicit-contract
// policy: only a same-file sibling guard COMBINED with the function's own
// null-check (self-guard) is strong enough for the AI. A self-guard-only row (no
// sibling reference), a sibling-only row (no self-guard), and a cross-file
// type-anchored sibling guard are all pre-dismissed into the ledger; the
// sibling+self-guard residual and legacy rows stay suspected.
func TestContractGapFilterEvidenceTiers(t *testing.T) {
	f := NewContractGapFilter(nil)
	kept, dropped, err := f.Apply(context.Background(), []Candidate{
		{FunctionName: "self_only", EvidenceKind: "self"},
		{FunctionName: "cross_file", EvidenceKind: "sibling-weak"},
		{FunctionName: "sibling_only", EvidenceKind: "sibling"},
		{FunctionName: "sibling_and_self_guard", EvidenceKind: "sibling", GuardLine: 42},
		{FunctionName: "legacy", EvidenceKind: ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 3 || len(kept) != 2 {
		t.Fatalf("kept=%d dropped=%d, want 2/3", len(kept), len(dropped))
	}
	if kept[0].FunctionName != "sibling_and_self_guard" || kept[1].FunctionName != "legacy" {
		t.Errorf("only sibling+self-guard/legacy rows may be kept, got %v", kept)
	}
	for _, d := range dropped {
		if d.Filter != "contract_gap" || d.Reason == "" {
			t.Errorf("dismissed row lacks provenance: %+v", d)
		}
	}
}
