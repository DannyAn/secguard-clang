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
		// Composite constant expressions that provably stay non-zero:
		{"(1u << 3)", true},    // non-zero literal shifted left
		{"24 * 60 * 60", true}, // multiplication chain
		{"(24 * 60 * 60)", true},
		{"1024 * 1024 * 1024", true},
		// Fixed-width overflow/UB is NOT folded (a wrap-around product or a
		// shift at/beyond the 32-bit evaluation width can become zero):
		{"1 << 63", false},                 // shift far past the width is UB
		{"1u << 32", false},                // shift at the unsigned 32-bit width is UB
		{"(1 << 62) * 4", false},           // product overflows int64
		{"(1u << 16) * (1u << 16)", false}, // 32-bit product wraps to zero
		// Operators that CAN zero out non-zero operands are NOT folded:
		{"2 / 2", false},
		{"5 % 5", false},
		{"6 - 6", false},
		{"6 - 5", false},
		{"8 >> 3", false},
		{"3 & 4", false},
		{"1 + 1", false},
		// Zero / unknown leaves:
		{"0 * 5", false},
		{"0 << 10", false},
		{"a * b", false}, // symbolic leaves need an env, absent here
		{"1e6", false},   // non-integer literal
		{"0.5", false},   // non-integer literal
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
#define SECONDS_PER_DAY (24 * 60 * 60)
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

	nonZero := []string{"BKT_NUM", "WORKERS", "FLAG", "SECONDS_PER_DAY", "HASH_SIZE", "MIN_COUNT", "CACHE_WAYS", "IMPLICIT_FIRST"}
	for _, name := range nonZero {
		if !env.NonZero(name) {
			t.Errorf("expected %q to be a non-zero constant", name)
		}
	}

	kept := []string{"ZERO_VAL", "FUNC", "FUNC()"}
	for _, name := range kept {
		if env.NonZero(name) {
			t.Errorf("did not expect %q to be classified non-zero", name)
		}
	}
}

func TestConstantEnvNonZeroExpr(t *testing.T) {
	env := NewConstantEnv()
	env.nonZero["HOURS"] = true
	env.nonZero["MINS"] = true
	env.nonZero["SECS"] = true

	cases := []struct {
		in   string
		want bool
	}{
		{"HOURS * MINS * SECS", true}, // symbolic multiplication folds
		{"24 * 60 * 60", true},        // literal multiplication folds
		{"1024 * 1024 * 1024", true},
		{"HOURS << 3", true}, // left shift of a non-zero symbol
		{"HOURS - MINS", false},
		{"HOURS / MINS", false},
		{"UNKNOWN * MINS", false}, // unknown leaf keeps the verdict
		{"0 * HOURS", false},
		{"", false},
	}
	for _, c := range cases {
		if got := env.NonZeroExpr(c.in); got != c.want {
			t.Errorf("NonZeroExpr(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
