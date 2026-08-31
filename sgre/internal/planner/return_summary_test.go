package planner

import "testing"

func TestLiteralInterval(t *testing.T) {
	cases := []struct {
		in string
		lo int64
		hi int64
		ok bool
	}{
		{"8", 8, 8, true},
		{"0", 0, 0, true},
		{"0x20", 32, 32, true},
		{"-1", -1, -1, true},
		{"4096u", 4096, 4096, true},
		{"(1u << 3)", 0, 0, false},
		{"1e6", 0, 0, false},
	}
	for _, c := range cases {
		iv, ok := literalInterval(c.in)
		if ok != c.ok {
			t.Errorf("literalInterval(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (iv.lo != c.lo || iv.hi != c.hi) {
			t.Errorf("literalInterval(%q) = [%d,%d], want [%d,%d]", c.in, iv.lo, iv.hi, c.lo, c.hi)
		}
	}
}

func TestCallNameFromDivisorText(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"get_count()", "get_count"},
		{"getpid()", "getpid"},
		{"(get_count())", "get_count"},
		{"(a - b)", ""},
		{"arr[i]", ""},
		{"d", ""},
		{"(unsigned)0", ""},
	}
	for _, c := range cases {
		if got := callNameFromDivisorText(c.in); got != c.want {
			t.Errorf("callNameFromDivisorText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
