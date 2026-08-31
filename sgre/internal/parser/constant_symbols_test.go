package parser

import "testing"

func TestNonZeroConstantValue(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"20", true},
		{"4096", true},
		{"0", false},
		{"0xFFFFFFFFu", true},
		{"0x20", true},
		{"-1", true},
		{"+8", true},
		{"sizeof(int)", true},
		{"(2048)", true},
		{"(1u << 3)", false}, // complex expr, conservatively unresolved
		{"1e6", false},       // non-integer literal
		{"0.5", false},       // non-integer literal
		{"", false},
	}
	for _, c := range cases {
		if got := NonZeroConstantValue(c.in); got != c.want {
			t.Errorf("NonZeroConstantValue(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCollectConstantSymbols(t *testing.T) {
	src := []byte(`#define BKT_NUM 4096
#define WORKERS 8
#define FLAG (1u << 3)
#define ZERO_VAL 0
#define FUNC(x) ((x) + 1)
enum { HASH_SIZE = 2048, MIN_COUNT = 1, IMPLICIT_FIRST };
const int CACHE_WAYS = 16;
int volatile_runtime(void);
`)
	p := NewParser()
	tree, err := p.Parse(src, "sym.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	env := CollectConstantSymbols(tree.RootNode())

	nonZero := []string{"BKT_NUM", "WORKERS", "HASH_SIZE", "MIN_COUNT", "CACHE_WAYS"}
	for _, name := range nonZero {
		if !env.NonZero(name) {
			t.Errorf("expected %q to be a non-zero constant", name)
		}
	}

	kept := []string{"FLAG", "ZERO_VAL", "FUNC", "IMPLICIT_FIRST"}
	for _, name := range kept {
		if env.NonZero(name) {
			t.Errorf("did not expect %q to be classified non-zero", name)
		}
	}
}
