package evidence

import (
	"reflect"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// relationalNonZeroVar is the divide-by-zero guard: a relational comparison
// whose constant bound excludes zero establishes the divisor as non-zero.
func TestRelationalNonZeroVar(t *testing.T) {
	src := `void f(int d) {
    if (d > 0) {}
    if (0 < d) {}
    if (d >= 1) {}
    if (d < 0) {}
    if (d <= -1) {}
    if (d > -1) {}
    if (d != 0) {}
}`
	tree, err := parser.NewParser().Parse([]byte(src), "relational.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := [][]string{{"d"}, {"d"}, {"d"}, {"d"}, {"d"}, nil, nil}
	conds := tree.RootNode().FindAll("binary_expression")
	if len(conds) != len(want) {
		t.Fatalf("found %d comparisons, want %d", len(conds), len(want))
	}
	for i, cond := range conds {
		if got := relationalNonZeroVar(cond); !reflect.DeepEqual(got, want[i]) {
			t.Errorf("relationalNonZeroVar #%d = %v, want %v", i, got, want[i])
		}
	}
}
