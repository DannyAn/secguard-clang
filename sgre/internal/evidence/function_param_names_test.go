//go:build !nosqlite

package evidence

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// functionParamNames must unwrap pointer_declarator layers around a function
// definition's declarator: a pointer-returning function (`T *f(T *p)`) wraps
// its function_declarator in pointer_declarator nodes, and skipping them makes
// the callee invisible to every detector that indexes parameters through this
// helper (caller_null, opaque_null, buffer_overflow, buffer_unchecked_index,
// contract_gap).
func TestFunctionParamNamesPointerReturning(t *testing.T) {
	src := `typedef struct { int x; } T;

T *ptr_ret(T *p) { return p; }

T **ptrptr_ret(int x) { return (T **)0; }

int plain_ret(T *p) { return p->x; }

void void_ret(void) {}

static T *static_ptr_ret(T *a, int *b) { return a; }
`
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]struct {
		names []string
		types []string
	}{}
	for _, fnDef := range tree.RootNode().FindAll("function_definition") {
		name, names, types := functionParamNames(fnDef)
		if name == "" {
			continue
		}
		got[name] = struct {
			names []string
			types []string
		}{names, types}
	}

	cases := []struct {
		fn       string
		wantName []string
		wantType []string
	}{
		{"ptr_ret", []string{"p"}, []string{"T *"}},
		{"ptrptr_ret", []string{"x"}, []string{"int"}},
		{"plain_ret", []string{"p"}, []string{"T *"}},
		{"void_ret", []string{""}, []string{"void"}},
		{"static_ptr_ret", []string{"a", "b"}, []string{"T *", "int *"}},
	}
	for _, tc := range cases {
		g, ok := got[tc.fn]
		if !ok {
			t.Errorf("%s: not indexed (pointer_declarator unwrap missing?)", tc.fn)
			continue
		}
		if len(g.names) != len(tc.wantName) {
			t.Errorf("%s: names = %v, want %v", tc.fn, g.names, tc.wantName)
			continue
		}
		for i := range tc.wantName {
			if g.names[i] != tc.wantName[i] {
				t.Errorf("%s: names[%d] = %q, want %q", tc.fn, i, g.names[i], tc.wantName[i])
			}
			if g.types[i] != tc.wantType[i] {
				t.Errorf("%s: types[%d] = %q, want %q", tc.fn, i, g.types[i], tc.wantType[i])
			}
		}
	}
}
