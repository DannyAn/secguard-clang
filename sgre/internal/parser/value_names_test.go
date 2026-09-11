package parser

import (
	"reflect"
	"sort"
	"testing"
)

func boundNamesOf(t *testing.T, src string) []string {
	t.Helper()
	p := NewParser()
	tree, err := p.Parse([]byte(src), "vn.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fns := tree.RootNode().FindAll("function_definition")
	if len(fns) == 0 {
		t.Fatal("no function found")
	}
	names := FunctionBoundNames(fns[0])
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func TestFunctionBoundNames_ParamsAndLocals(t *testing.T) {
	src := `typedef void *handle_t;
struct S { int n; };
static unsigned int load_s(unsigned char *in, unsigned int len, struct S *out) {
    struct S tmp;
    handle_t h;
    unsigned char *base;
    int a = 0, b;
    char buf[8];
    int (*fp)(int x);
    if (len < 1) { int inner; return inner; }
    out->n = in[0];
    return 1;
}
`
	got := boundNamesOf(t, src)
	want := []string{"a", "b", "base", "buf", "fp", "h", "in", "inner", "len", "out", "tmp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FunctionBoundNames =\n %v\nwant\n %v", got, want)
	}
}

// TestFunctionBoundNames_NeverCollectsTypeNames is the guard for the dangerous
// direction: a type name classified as a value would make a real `(T)&x` cast
// look like a bit-and and resurrect the out-parameter false positives.
func TestFunctionBoundNames_NeverCollectsTypeNames(t *testing.T) {
	src := `typedef void *shm_handle;
typedef struct cfg_waf_vsys_list cfg_waf_vsys_list;
enum E { E_A };
union U { int x; };
void cfg_parse(const char *cfg, shm_handle **out) {
    struct cfg_waf_vsys_list *prfs_list;
    cfg_waf_vsys_list value;
    enum E e;
    union U u;
    shm_handle h;
    *out = 0;
}
`
	names := boundNamesOf(t, src)
	for _, typeName := range []string{"shm_handle", "cfg_waf_vsys_list", "E", "U", "S"} {
		for _, n := range names {
			if n == typeName {
				t.Errorf("type name %q must never be collected as a bound value (got %v)", typeName, names)
			}
		}
	}
	for _, v := range []string{"cfg", "out", "prfs_list", "value", "e", "u", "h"} {
		found := false
		for _, n := range names {
			if n == v {
				found = true
			}
		}
		if !found {
			t.Errorf("declarator %q should be collected, got %v", v, names)
		}
	}
}

func TestFunctionBoundNamesByBody_NonFunction(t *testing.T) {
	p := NewParser()
	tree, _ := p.Parse([]byte("int g;\n"), "vn.c")
	if names := FunctionBoundNamesByBody(tree.RootNode()); names != nil {
		t.Errorf("a non-function body must yield a nil oracle, got %v", names)
	}
}
