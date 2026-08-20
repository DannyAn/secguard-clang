package planner

import "testing"

func TestCWEForType_AllRegisteredTypesHaveCWE(t *testing.T) {
	for _, name := range AllVulnTypes() {
		if CWEForType(name) == "" {
			t.Errorf("vuln type %q has no CWE — every VulnTypeSpec must set CWE", name)
		}
	}
}

func TestCWEForType_KnownMappings(t *testing.T) {
	cases := []struct{ vuln, cwe string }{
		{"null-deref", "CWE-476"},
		{"buffer-overflow", "CWE-787"},
		{"out-of-bounds", "CWE-125"},
		{"divide-by-zero", "CWE-369"},
		{"unchecked-return", "CWE-252"},
		{"path-traversal", "CWE-22"},
		{"signed-compare", "CWE-681"},
		{"sizeof-misuse", "CWE-467"},
		{"injection", "CWE-78"},
	}
	for _, c := range cases {
		if got := CWEForType(c.vuln); got != c.cwe {
			t.Errorf("CWEForType(%q) = %q, want %q", c.vuln, got, c.cwe)
		}
	}
}

func TestCWEForType_UnknownTypeReturnsEmpty(t *testing.T) {
	if got := CWEForType("nonexistent"); got != "" {
		t.Errorf("CWEForType unknown type = %q, want empty", got)
	}
}

func TestTypeForCWE_RoundTrip(t *testing.T) {
	for _, name := range AllVulnTypes() {
		cwe := CWEForType(name)
		if cwe == "" {
			continue
		}
		got := TypeForCWE(cwe)
		if got != name {
			t.Errorf("TypeForCWE(CWEForType(%q)) = %q, want %q", name, got, name)
		}
	}
}

func TestTypeForCWE_CaseInsensitive(t *testing.T) {
	if got := TypeForCWE("cwe-476"); got != "null-deref" {
		t.Errorf("TypeForCWE(\"cwe-476\") = %q, want null-deref", got)
	}
}

func TestTypeForCWE_LegacyCWEs(t *testing.T) {
	cases := map[string]string{
		"CWE-89":  "injection",
		"cwe-326": "crypto-misuse",
		"CWE-338": "crypto-misuse",
	}
	for cwe, want := range cases {
		if got := TypeForCWE(cwe); got != want {
			t.Errorf("TypeForCWE(%q) = %q, want %q (legacy CWE must reverse-map)", cwe, got, want)
		}
	}
}

func TestAllCWEs_IncludesLegacyCWE89(t *testing.T) {
	cwes := AllCWEs()
	if !cwes["CWE-89"] {
		t.Error("AllCWEs() must include legacy CWE-89 for backward-compatible injection findings")
	}
	if !cwes["CWE-78"] {
		t.Error("AllCWEs() must include CWE-78 (canonical injection)")
	}
}

func TestAllCWEs_IncludesLegacyCryptoCWEs(t *testing.T) {
	cwes := AllCWEs()
	if !cwes["CWE-326"] {
		t.Error("AllCWEs() must include legacy CWE-326 (undersized key) for crypto-misuse")
	}
	if !cwes["CWE-338"] {
		t.Error("AllCWEs() must include legacy CWE-338 (weak PRNG) for crypto-misuse")
	}
	if !cwes["CWE-327"] {
		t.Error("AllCWEs() must include CWE-327 (canonical crypto-misuse)")
	}
}

func TestAllCWEs_ContainsAll20CanonicalCWEs(t *testing.T) {
	cwes := AllCWEs()
	expected := []string{
		"CWE-476", "CWE-787", "CWE-125", "CWE-401", "CWE-78",
		"CWE-404", "CWE-457", "CWE-416", "CWE-415", "CWE-134",
		"CWE-190", "CWE-362", "CWE-798", "CWE-667", "CWE-327",
		"CWE-369", "CWE-252", "CWE-22", "CWE-681", "CWE-467",
	}
	for _, cwe := range expected {
		if !cwes[cwe] {
			t.Errorf("AllCWEs() missing canonical %q", cwe)
		}
	}
}

func TestAllCWEs_CountIs20CanonicalPlus3Legacy(t *testing.T) {
	cwes := AllCWEs()
	// 20 canonical + 3 legacy (CWE-89, CWE-326, CWE-338) = 23
	if len(cwes) != 23 {
		t.Errorf("AllCWEs() has %d entries, want 23 (20 canonical + 3 legacy: CWE-89, CWE-326, CWE-338)", len(cwes))
	}
}

func TestCryptoMisuse_CategoryConfidence(t *testing.T) {
	spec, err := GetVulnTypeSpec("crypto-misuse")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"weak_algorithm": "confirmed",
		"undersized_key": "confirmed",
		"weak_random":    "suspected",
	}
	for category, want := range cases {
		if got := spec.CategoryConfidence[category]; got != want {
			t.Errorf("crypto-misuse category %q confidence = %q, want %q", category, got, want)
		}
	}
}

func TestInjection_ConvergeKey_DistinctSinks(t *testing.T) {
	spec, err := GetVulnTypeSpec("injection")
	if err != nil {
		t.Fatal(err)
	}
	// Two independent sqlite3_exec sinks in one function must not merge.
	a := Candidate{FileID: 1, FunctionName: "f", Category: "sql_injection", VariableName: "q1", Line: 10}
	b := Candidate{FileID: 1, FunctionName: "f", Category: "sql_injection", VariableName: "q2", Line: 20}
	if spec.ConvergeKey(a) == spec.ConvergeKey(b) {
		t.Errorf("distinct buffers q1/q2 must produce distinct converge keys")
	}
	// A sprintf source and its sqlite3_exec sink sharing one buffer must merge.
	src := Candidate{FileID: 1, FunctionName: "f", Category: "sql_injection", VariableName: "query", Line: 48}
	sink := Candidate{FileID: 1, FunctionName: "f", Category: "sql_injection", VariableName: "query", Line: 49}
	if spec.ConvergeKey(src) != spec.ConvergeKey(sink) {
		t.Errorf("sprintf source and sqlite3_exec sink sharing buffer must merge")
	}
}

func TestNullDeref_EvidenceRoles(t *testing.T) {
	spec, err := GetVulnTypeSpec("null-deref")
	if err != nil {
		t.Fatal(err)
	}
	frags := spec.BuildEvidence(Candidate{
		FunctionName:      "f",
		VariableName:      "p",
		Line:              42,
		HasNullableSource: true,
		IsReachable:       true,
		HasDataFlow:       true,
	})
	roles := map[string]bool{}
	for _, e := range frags {
		roles[e.Role] = true
	}
	if !roles["source"] || !roles["path"] {
		t.Errorf("null-deref evidence should carry source + path roles, got %v", roles)
	}

	def := spec.BuildEvidence(Candidate{
		FunctionName:    "f",
		VariableName:    "p",
		Line:            42,
		HasDefiniteNull: true,
	})
	for _, e := range def {
		if e.Role == "condition" {
			return
		}
	}
	t.Errorf("null-deref definite-null evidence should carry a condition role, got %+v", def)
}
