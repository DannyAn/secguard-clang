package evidence

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestFindFieldTypeName(t *testing.T) {
	src := `struct S { int a; long a; char *b; char *c; };
struct T { char *b; };`
	tree, err := parser.NewParser().Parse([]byte(src), "fieldtype.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	bc := &bufCtx{fields: tree.RootNode().FindAll("field_declaration")}
	for i, f := range bc.fields {
		var k []string
		for _, c := range f.NamedChildren() {
			k = append(k, c.Kind()+":"+c.Text())
		}
		t.Logf("field %d type=%q children=%v", i, typeSpelling(f), k)
	}
	if got := findFieldTypeName(bc, "a"); got != "" {
		t.Errorf("ambiguous field type = %q, want empty", got)
	}
	if got := findFieldTypeName(bc, "b"); got != "char *" {
		t.Errorf("consistent field type = %q, want %q", got, "char *")
	}
	if got := findFieldTypeName(bc, "missing"); got != "" {
		t.Errorf("missing field type = %q, want empty", got)
	}
}
