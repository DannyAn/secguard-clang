package planner

import "testing"

// TestFormatConversions pins the format-aware half of the constant-path proof:
// integer/float conversions can only emit digits and signs (never a path
// separator), so their argument is exempt from the constant requirement; a
// string/char conversion emits arbitrary bytes and its argument must be
// constant. A format the analyzer cannot read confidently reports ok=false so
// the caller falls back to the conservative "every argument must be constant".
func TestFormatConversions(t *testing.T) {
	cases := []struct {
		format string
		want   []bool
		ok     bool
	}{
		{"%s/%s", []bool{false, false}, true},
		{"%s/%u.json", []bool{false, true}, true},
		{"%s/%s_%u.gz", []bool{false, false, true}, true},
		{"%d%%-%02x", []bool{true, true}, true},
		{"%.3f|%lld|%zu", []bool{true, true, true}, true},
		{"%p", []bool{true}, true},
		{"%c", []bool{false}, true},
		{"plain", nil, true},
		{"%*s", nil, false},
		{"%n", nil, false},
		{"%q", nil, false},
		{"dangling %", nil, false},
	}
	for _, tc := range cases {
		got, ok := formatConversions(tc.format)
		if ok != tc.ok {
			t.Errorf("formatConversions(%q) ok = %v, want %v", tc.format, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("formatConversions(%q) = %v, want %v", tc.format, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("formatConversions(%q) = %v, want %v", tc.format, got, tc.want)
				break
			}
		}
	}
}

func TestArgIsReadOnly(t *testing.T) {
	cases := []struct {
		name string
		idx  int
		want bool
	}{
		{"fopen", 0, true},
		{"openat", 1, true},
		{"openat", 0, false},
		{"strlen", 0, true},
		{"printf", 3, true},
		{"fill_path", 0, false},
		{"rename", 1, true},
	}
	for _, tc := range cases {
		if got := argIsReadOnly(tc.name, tc.idx); got != tc.want {
			t.Errorf("argIsReadOnly(%q, %d) = %v, want %v", tc.name, tc.idx, got, tc.want)
		}
	}
}
