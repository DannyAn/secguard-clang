package planner

import "testing"

func TestBuildHint(t *testing.T) {
	dbz := &VulnTypeSpec{Name: "divide-by-zero"}
	cases := []struct {
		name string
		c    Candidate
		spec *VulnTypeSpec
		want string
	}{
		{"certain null with source line", Candidate{SourceLine: 10, HasDefiniteNull: true}, nil, "src@10 certain-null"},
		{"maybe null with source line", Candidate{SourceLine: 20, HasNullableSource: true}, nil, "src@20 maybe-null"},
		{"taint source", Candidate{HasTaintSource: true}, nil, "tainted"},
		{"weak guard", Candidate{GuardStrength: "weak"}, nil, "weak-guard"},
		{"no flow facts", Candidate{}, nil, "—"},
		{"taint wins over null tier", Candidate{HasNullableSource: true, HasTaintSource: true}, nil, "maybe-null tainted"},
		{"divide-by-zero bare divisor", Candidate{VariableName: "n"}, dbz, "divisor@bare"},
		{"divide-by-zero call divisor", Candidate{VariableName: "get_count()"}, dbz, "divisor@call"},
		{"divide-by-zero compound divisor", Candidate{VariableName: "(a - b)"}, dbz, "divisor@compound"},
		{"divide-by-zero field divisor", Candidate{VariableName: "graph->gran_time"}, dbz, "divisor@field"},
		{"divide-by-zero global divisor", Candidate{VariableName: "g_count"}, dbz, "divisor@global"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildHint(tc.c, tc.spec); got != tc.want {
				t.Errorf("buildHint() = %q, want %q", got, tc.want)
			}
		})
	}
}
