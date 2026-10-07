package parser

import "testing"

func TestAssignPartsInitDeclAttribute(t *testing.T) {
	cases := []struct {
		src    string
		wantLHS string
		wantRHS string
	}{
		{`int x = 0;`, "x", "0"},
		{`int x __attribute__((aligned(16))) = 0;`, "x", "0"},
		{`int *p __attribute__((cleanup(f))) = malloc(10);`, "*p", "malloc(10)"},
		{`int a[2] __attribute__((packed)) = {1, 2};`, "a[2]", "{1, 2}"},
	}
	for _, tc := range cases {
		p := NewParser()
		tree, err := p.Parse([]byte(tc.src), "probe.c")
		if err != nil {
			t.Fatalf("parse %q: %v", tc.src, err)
		}
		inits := tree.RootNode().FindAll("init_declarator")
		if len(inits) != 1 {
			t.Fatalf("parse %q: want 1 init_declarator, got %d", tc.src, len(inits))
		}
		lhs, rhs, ok := inits[0].AssignParts()
		if !ok {
			t.Fatalf("AssignParts %q: ok=false", tc.src)
		}
		if lhs.Text() != tc.wantLHS || rhs.Text() != tc.wantRHS {
			t.Errorf("AssignParts %q = (%q, %q), want (%q, %q)", tc.src, lhs.Text(), rhs.Text(), tc.wantLHS, tc.wantRHS)
		}
		tree.Close()
		p.CloseAll()
	}
}
