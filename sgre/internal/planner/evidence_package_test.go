package planner

import "testing"

func TestBuildHint(t *testing.T) {
	cases := []struct {
		name string
		c    Candidate
		want string
	}{
		{"certain null with source line", Candidate{SourceLine: 10, HasDefiniteNull: true}, "src@10 certain-null"},
		{"maybe null with source line", Candidate{SourceLine: 20, HasNullableSource: true}, "src@20 maybe-null"},
		{"taint source", Candidate{HasTaintSource: true}, "tainted"},
		{"weak guard", Candidate{GuardStrength: "weak"}, "weak-guard"},
		{"no flow facts", Candidate{}, "—"},
		{"taint wins over null tier", Candidate{HasNullableSource: true, HasTaintSource: true}, "maybe-null tainted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildHint(tc.c); got != tc.want {
				t.Errorf("buildHint() = %q, want %q", got, tc.want)
			}
		})
	}
}
