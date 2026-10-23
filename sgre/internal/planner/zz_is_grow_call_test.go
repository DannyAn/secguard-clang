//go:build !nosqlite

package planner

import "testing"

// NP-06: isGrowCall matched by raw substring, so `growth_rate` (contains
// "grow") and `growing_pains` were treated as capacity-growth calls. Match on
// `_`-separated word tokens instead; a name like `ensure_capacity_log` still
// hits the `ensure` token, but the size>idx argument form in growCallCovers
// is what actually disarms a dismissal, so a log-only namesake cannot
// suppress a candidate.
func TestIsGrowCallWordBoundary(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"deque_grow", true},
		{"resize_pool", true},
		{"ensure_capacity", true},
		{"expand_buffer", true},
		{"extend_vec", true},
		{"reserve_slots", true},
		{"growth_rate", false},
		{"growing_pains", false},
		{"displace_item", false},
		{"registrar", false},
	}
	for _, tc := range cases {
		if got := isGrowCall(tc.name); got != tc.want {
			t.Errorf("isGrowCall(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
