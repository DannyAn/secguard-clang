package macros

import "testing"

func TestGuardParamsInBody(t *testing.T) {
	cases := []struct {
		name           string
		body           string
		params         []string
		wantPlain      map[int]bool
		wantNegated    map[int]bool
	}{
		{
			name:        "non-negated condition",
			body:        "if ((cond)) { return ret; }",
			params:      []string{"cond", "ret"},
			wantPlain:   map[int]bool{0: true},
			wantNegated: map[int]bool{},
		},
		{
			name:        "negated variable",
			body:        "if (!(ptr)) { return ret; }",
			params:      []string{"ptr", "ret"},
			wantPlain:   map[int]bool{},
			wantNegated: map[int]bool{0: true},
		},
		{
			name:        "no return is not a guard",
			body:        "if ((cond)) { x = 1; }",
			params:      []string{"cond"},
			wantPlain:   map[int]bool{},
			wantNegated: map[int]bool{},
		},
		{
			name:        "multi-line layout",
			body:        "if ((cond)) {                              \\\n        return ret;                            \\\n    }",
			params:      []string{"cond", "ret"},
			wantPlain:   map[int]bool{0: true},
			wantNegated: map[int]bool{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain, negated := guardParamsInBody(tc.body, tc.params)
			if !equalBoolMap(plain, tc.wantPlain) {
				t.Errorf("plain = %v, want %v", plain, tc.wantPlain)
			}
			if !equalBoolMap(negated, tc.wantNegated) {
				t.Errorf("negated = %v, want %v", negated, tc.wantNegated)
			}
		})
	}
}

func equalBoolMap(a, b map[int]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
