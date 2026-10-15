package planner

import (
	"testing"
)

func TestBuildHint(t *testing.T) {
	dbz := &VulnTypeSpec{Name: "divide-by-zero"}
	uninit := &VulnTypeSpec{Name: "uninit"}
	iof := &VulnTypeSpec{Name: "integer-overflow"}
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
		{"api and category", Candidate{APIName: "memcpy", Category: "buffer_overflow"}, nil, "api@memcpy cat@buffer_overflow"},
		{"uninit certain", Candidate{SuspicionLevel: "confirmed"}, uninit, "certain-uninit"},
		{"uninit maybe", Candidate{SuspicionLevel: "suspected"}, uninit, "maybe-uninit"},
		{"integer-overflow unsigned sub unguarded", Candidate{Category: "unsigned_sub_underflow"}, iof, "guard@none cat@unsigned_sub_underflow"},
		{"integer-overflow unsigned sub provenance", Candidate{Category: "unsigned_sub_underflow", LHSKind: "param", RHSKind: "local", SubRHSInfluenced: true, SubSink: "call_arg"}, iof, "lhs@param rhs@local rhs-influenced sink@call_arg guard@none cat@unsigned_sub_underflow"},
		{"integer-overflow size calc (no guard tag)", Candidate{Category: "size_calc_overflow"}, iof, "cat@size_calc_overflow"},
		{"unchecked-return contract known", Candidate{ContractKnown: true, APIName: "malloc", Category: "unchecked_return"}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@known api@malloc cat@unchecked_return"},
		{"unchecked-return contract unknown", Candidate{ContractKnown: false, APIName: "my_alloc", Category: "unchecked_return"}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@unknown api@my_alloc cat@unchecked_return"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildHint(tc.c, tc.spec); got != tc.want {
				t.Errorf("buildHint() = %q, want %q", got, tc.want)
			}
		})
	}
}
func TestNewEvidenceItem_UncheckedReturnContract(t *testing.T) {
	spec := &VulnTypeSpec{Name: "unchecked-return", EvidenceType: "UNCHECKED_RETURN", BuildEvidence: func(c Candidate) []EvidenceFragment { return nil }}

	c1 := Candidate{ContractKnown: true, FunctionName: "f", Line: 10}
	item1 := newEvidenceItem(c1, spec, "test.c")
	if item1.Contract != "known" {
		t.Errorf("contractKnown=true: Contract should be known, got %q", item1.Contract)
	}

	c2 := Candidate{ContractKnown: false, FunctionName: "f", Line: 10}
	item2 := newEvidenceItem(c2, spec, "test.c")
	if item2.Contract != "unknown" {
		t.Errorf("contractKnown=false: Contract should be unknown, got %q", item2.Contract)
	}
}
