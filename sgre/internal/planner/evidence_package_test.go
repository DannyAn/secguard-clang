package planner

import (
	"strings"
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
		{"unchecked-return contract unknown with callee def", Candidate{ContractKnown: false, APIName: "obj_pool_new", Category: "unchecked_return", CalleeDefFile: "/srv/app/pool.c", CalleeDefLine: 42}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@unknown callee@pool.c:42 api@obj_pool_new cat@unchecked_return"},
		{"unchecked-return contract known ignores callee def", Candidate{ContractKnown: true, APIName: "obj_pool_new", Category: "unchecked_return", CalleeDefFile: "/srv/app/pool.c", CalleeDefLine: 42}, &VulnTypeSpec{Name: "unchecked-return"}, "contract@known api@obj_pool_new cat@unchecked_return"},
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

// E-03 regression: contract@unknown evidence must carry the callee's definition
// location (or an explicit "no body in scan") — the classifier's proof burden
// ("prove the callee returns a failure sentinel or dismiss") cannot be met from
// a ±8 window when the callee is a static factory in another file.
func TestBuildEvidence_UncheckedReturnCalleeDefinition(t *testing.T) {
	spec, err := GetVulnTypeSpec("unchecked-return")
	if err != nil {
		t.Fatal(err)
	}
	join := func(frags []EvidenceFragment) string {
		var sb strings.Builder
		for _, f := range frags {
			sb.WriteString(f.Detail)
			sb.WriteString("\n")
		}
		return sb.String()
	}

	def := join(spec.BuildEvidence(Candidate{
		APIName: "obj_pool_new", FunctionName: "handle", Line: 10,
		CalleeDefFile: "pool.c", CalleeDefLine: 42, CalleeDefSignature: "Obj *obj_pool_new(int n)",
	}))
	if !strings.Contains(def, "callee obj_pool_new is defined in the scan at pool.c:42") {
		t.Errorf("in-scan callee: evidence must carry the definition location:\n%s", def)
	}
	if !strings.Contains(def, "signature: Obj *obj_pool_new(int n)") {
		t.Errorf("in-scan callee: evidence must carry the callee signature:\n%s", def)
	}

	ext := join(spec.BuildEvidence(Candidate{APIName: "ext_buf_dup", FunctionName: "handle_ext", Line: 5}))
	if !strings.Contains(ext, "callee ext_buf_dup has no definition in the scan") {
		t.Errorf("external callee: evidence must say no definition in scan:\n%s", ext)
	}

	known := join(spec.BuildEvidence(Candidate{APIName: "malloc", FunctionName: "f", Line: 3, ContractKnown: true}))
	if strings.Contains(known, "callee_definition") || strings.Contains(known, "no definition in the scan") {
		t.Errorf("contract@known: callee-definition fragment must not appear:\n%s", known)
	}
}

// E-05, param half: taint that enters through a caller's argument has no
// in-function origin statement — the fragment must say where the taint enters
// instead of sending the classifier to hunt a source the window cannot hold.
func TestTaintSourceDetail_ParamOrigin(t *testing.T) {
	inj, err := GetVulnTypeSpec("injection")
	if err != nil {
		t.Fatal(err)
	}
	frags := inj.BuildEvidence(Candidate{HasTaintSource: true, FunctionName: "f", Line: 9})
	found := false
	for _, f := range frags {
		if f.Type == "taint_source" {
			found = true
			if !strings.Contains(f.Detail, "tainted parameter") || !strings.Contains(f.Detail, "CALLER") {
				t.Errorf("param-origin taint fragment must say the taint enters from a caller:\n%s", f.Detail)
			}
		}
	}
	if !found {
		t.Errorf("taint_source fragment missing: %+v", frags)
	}
}
