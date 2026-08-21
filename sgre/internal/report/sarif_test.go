package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestWriteSarifFromFindings(t *testing.T) {
	dir := t.TempDir()
	sarifPath := filepath.Join(dir, "result.sarif")

	findings := []*db.Finding{
		{
			RuleID: "CWE-252", Severity: "high", Confidence: 0.9,
			Status: "confirmed", ReviewStatus: "",
			FilePath: "src/a.c", LineNumber: 13, FunctionName: "f",
			Summary: "malloc 未判空即解引用", Reasoning: "分配后立即解引用",
			ExceptionCheck: "无 safe wrapper", FixStrategy: "if (p == NULL) return -1;",
		},
		{
			RuleID: "CWE-190", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "suspected-kept",
			FilePath: "src/b.c", LineNumber: 35, FunctionName: "g",
			Summary: "n+1 可溢出", Reasoning: "仅 n==SIZE_MAX 时回绕",
		},
		{
			RuleID: "CWE-476", Severity: "high", Confidence: 0.5,
			Status: "suspected", ReviewStatus: "dismissed",
			FilePath: "src/c.c", LineNumber: 7, FunctionName: "h",
			Summary: "误报", Reasoning: "已有 NULL 守卫",
		},
	}

	if err := WriteSarifFromFindings(sarifPath, "", findings); err != nil {
		t.Fatalf("WriteSarifFromFindings: %v", err)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("read result.sarif: %v", err)
	}
	var rep sarifReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}

	results := rep.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results (dismissed excluded), got %d", len(results))
	}

	// First result is confirmed with fix + properties.
	if results[0].Level != "error" {
		t.Errorf("confirmed finding level = %q, want error", results[0].Level)
	}
	if len(results[0].Fixes) != 1 || results[0].Fixes[0].Description.Text != "if (p == NULL) return -1;" {
		t.Errorf("confirmed finding should carry fix_strategy, got %+v", results[0].Fixes)
	}
	if results[0].Properties["reasoning"] != "分配后立即解引用" {
		t.Errorf("properties.reasoning not carried, got %+v", results[0].Properties)
	}

	// Second result is suspected-kept -> warning, no fix.
	if results[1].Level != "warning" {
		t.Errorf("suspected finding level = %q, want warning", results[1].Level)
	}
	if len(results[1].Fixes) != 0 {
		t.Errorf("suspected finding without fix_strategy should have no fixes, got %+v", results[1].Fixes)
	}
}

// The candidate stage and the verdict stage must never share a file: a CI gate
// reading result.sarif must be unable to see unclassified candidates, and the
// candidate report must not present leads as errors.
func TestSarifStages_SeparateFilesAndSeverity(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{
		ScanDir:             dir,
		ScanID:              "sc_test",
		SarifPath:           filepath.Join(dir, SarifFile),
		CandidatesSarifPath: filepath.Join(dir, CandidatesSarifFile),
		ReportPath:          filepath.Join(dir, ReportFile),
	}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "confirmed",
			Target:         planner.TargetInfo{File: "/repo/src/a.c", Function: "f", Line: 13, Variable: "p"},
			Evidence:       []planner.EvidenceFragment{{Role: "source", Detail: "p may be null"}},
		}},
	}}
	if err := o.Write(pkgs, IndexSummary{}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(o.SarifPath); !os.IsNotExist(err) {
		t.Errorf("%s must not exist before classification (err=%v)", SarifFile, err)
	}
	data, err := os.ReadFile(o.CandidatesSarifPath)
	if err != nil {
		t.Fatalf("read %s: %v", CandidatesSarifFile, err)
	}
	var candidateReport struct {
		Runs []struct {
			Properties map[string]string `json:"properties"`
			Results    []struct {
				Level      string            `json:"level"`
				Properties map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &candidateReport); err != nil {
		t.Fatal(err)
	}
	run := candidateReport.Runs[0]
	if run.Properties["stage"] != "candidates" {
		t.Errorf("run stage = %q, want candidates", run.Properties["stage"])
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	if run.Results[0].Level != "note" {
		t.Errorf("candidate level = %q, want note (an unclassified lead is not an error)", run.Results[0].Level)
	}
	// The pipeline prior stays available, but only as a labelled property.
	if run.Results[0].Properties["suspicion_level"] != "confirmed" {
		t.Errorf("suspicion_level property = %q, want confirmed", run.Results[0].Properties["suspicion_level"])
	}

	// The verdict stage writes its own file, at real severities.
	findings := []*db.Finding{{
		RuleID: "CWE-476", FilePath: "/repo/src/a.c", LineNumber: 13, FunctionName: "f",
		Status: "confirmed", Severity: "high", Confidence: 0.9, Summary: "real",
	}}
	if err := WriteSarifFromFindings(o.SarifPath, "", findings); err != nil {
		t.Fatal(err)
	}
	vdata, err := os.ReadFile(o.SarifPath)
	if err != nil {
		t.Fatal(err)
	}
	var verdictReport struct {
		Runs []struct {
			Properties map[string]string `json:"properties"`
			Results    []struct {
				Level string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(vdata, &verdictReport); err != nil {
		t.Fatal(err)
	}
	if verdictReport.Runs[0].Properties["stage"] != "findings" {
		t.Errorf("verdict run stage = %q, want findings", verdictReport.Runs[0].Properties["stage"])
	}
	if verdictReport.Runs[0].Results[0].Level != "error" {
		t.Errorf("confirmed verdict level = %q, want error", verdictReport.Runs[0].Results[0].Level)
	}
}
