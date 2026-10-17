package planner

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestBenchmarkValidatorCWEMap is the cross-artifact guard for the benchmark
// validator's CWE-to-vuln-type table. The validator matches SARIF results by
// ruleId, and a ruleId is the CWE the pipeline emitted — which for a
// multi-CWE type (injection: CWE-78/89/88/93/117) is NOT just the type's
// canonical CWE. A missing entry silently makes every finding of that CWE
// unmatchable (the TP-02 SQL-injection false negative: the finding existed at
// the right line but `CWE-89` fell through unmapped, so the type comparison
// never happened).
//
// planner.AllCWEs() is the single source of truth for "which CWE identifiers can
// appear in a result", so the validator's map must cover every one of them and
// map it back to the type TypeForCWE reports.
func TestBenchmarkValidatorCWEMap(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "c-vuln-benchmark", "scripts", "validate-benchmark.py")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("benchmark validator not available (%v) — nothing to guard", err)
	}

	// The CWE_TO_TYPE dict is a flat {"CWE-xxx": "type", ...} block.
	blockRE := regexp.MustCompile(`(?s)CWE_TO_TYPE\s*=\s*\{(.*?)\n\}`)
	block := blockRE.FindSubmatch(data)
	if block == nil {
		t.Fatalf("CWE_TO_TYPE block not found in %s", path)
	}
	entryRE := regexp.MustCompile(`"(CWE-\d+)"\s*:\s*"([a-z0-9-]+)"`)
	got := map[string]string{}
	for _, m := range entryRE.FindAllSubmatch(block[1], -1) {
		got[string(m[1])] = string(m[2])
	}
	if len(got) == 0 {
		t.Fatalf("CWE_TO_TYPE parsed empty from %s", path)
	}

	for cwe := range AllCWEs() {
		want := TypeForCWE(cwe)
		if want == "" {
			continue // not a registered vuln-type CWE
		}
		typ, ok := got[cwe]
		if !ok {
			t.Errorf("validate-benchmark.py CWE_TO_TYPE is missing %s (%s) — a finding with that ruleId would silently never match", cwe, want)
			continue
		}
		if typ != want {
			t.Errorf("validate-benchmark.py maps %s to %q, planner.TypeForCWE says %q", cwe, typ, want)
		}
	}
}
