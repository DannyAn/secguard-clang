package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

// cweChainPackages is the root-cause-chain fixture: ONE out-of-bounds finding
// carrying the consequence CWE, the shape the unchecked-external-index channel
// emits (CWE-125 root cause, downstream null deref).
func cweChainPackages() []*planner.PlanResult {
	return []*planner.PlanResult{{
		VulnerabilityType: "out-of-bounds",
		Candidates: []planner.EvidenceItem{{
			VulnerabilityType: "out-of-bounds",
			SuspicionLevel:    "suspected",
			Category:          "array_oob_read_unchecked",
			CWEChain:          "CWE-125 → CWE-476",
			Target: planner.TargetInfo{
				File: "/repo/src/rbl.c", Function: "show_active", Line: 29, Variable: "rbl_profile->svr[idx]",
			},
			Hint:       "buf@rbl_profile->svr cap@4 idx@idx idx-src@actived_index elem-field@domain oob-escape@maf_show cwe-chain@CWE-125→CWE-476",
			HintTokens: []string{"buf@rbl_profile->svr", "cap@4", "idx@idx", "idx-src@actived_index", "elem-field@domain", "oob-escape@maf_show", "cwe-chain@CWE-125→CWE-476"},
			Evidence:   []planner.EvidenceFragment{{Role: "sink", Detail: "out-of-bounds access"}},
		}},
	}}
}

func TestWriteCandidates_VulnerabilityChainSection(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	if err := o.writeCandidates(cweChainPackages()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, CandidatesDir, "out-of-bounds", "001_src_rbl_c_29.md"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "## Vulnerability Chain") {
		t.Errorf("candidate file must carry the Vulnerability Chain section:\n%s", content)
	}
	if !strings.Contains(content, "`CWE-125 → CWE-476`") {
		t.Errorf("the chain must state both CWEs:\n%s", content)
	}
	if !strings.Contains(content, "Report ONE finding") {
		t.Errorf("the chain section must forbid a duplicate finding:\n%s", content)
	}
	// The section sits between the fact inventory and the narrative evidence.
	chainIdx := strings.Index(content, "## Vulnerability Chain")
	evidenceIdx := strings.Index(content, "## Evidence")
	factsIdx := strings.Index(content, "## Verdict Facts")
	if chainIdx < 0 || evidenceIdx < 0 {
		t.Fatalf("missing sections: chain=%d evidence=%d", chainIdx, evidenceIdx)
	}
	if !(chainIdx < evidenceIdx) || (factsIdx >= 0 && factsIdx > chainIdx) {
		t.Errorf("section order must be ... Verdict Facts → Vulnerability Chain → Evidence (facts=%d chain=%d evidence=%d)", factsIdx, chainIdx, evidenceIdx)
	}
}

func TestWriteCandidatesSarif_CWEChainProperty(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	if err := o.writeCandidatesSarif(cweChainPackages()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, CandidatesSarifFile))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Runs []struct {
			Results []struct {
				Properties map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal candidates sarif: %v", err)
	}
	if len(rep.Runs) == 0 || len(rep.Runs[0].Results) == 0 {
		t.Fatalf("no results in candidates sarif")
	}
	if got := rep.Runs[0].Results[0].Properties["cwe_chain"]; got != "CWE-125 → CWE-476" {
		t.Errorf("cwe_chain property = %q, want the root-cause chain", got)
	}
}
