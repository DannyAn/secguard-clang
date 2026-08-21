package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func candidatePackages() []*planner.PlanResult {
	return []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "confirmed",
			Target: planner.TargetInfo{
				File: "/repo/src/a.c", Function: "f", Line: 13, Variable: "p",
			},
			Evidence: []planner.EvidenceFragment{
				{Role: "source", Detail: "p assigned a possibly-null value"},
			},
		}},
	}}
}

// The candidate stage must not look like a verdict: a file that says
// "Suspicion Level: confirmed" next to "Status: pending" made reviewers read a
// pipeline prior as an AI conclusion.
func TestWriteCandidates_NoVerdictLanguage(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	if err := o.writeCandidates(candidatePackages()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, CandidatesDir, "null-deref", "001_src_a_c_13.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("candidate evidence should live under %s/: %v", CandidatesDir, err)
	}
	content := string(data)

	if strings.Contains(content, "**Status:**") {
		t.Errorf("candidate file must not carry a Status line (it has no verdict):\n%s", content)
	}
	if strings.Contains(content, "_pending_") {
		t.Errorf("candidate file must not claim a pending verdict:\n%s", content)
	}
	if !strings.Contains(content, "pipeline prior, not a verdict") {
		t.Errorf("suspicion level must be labelled as a pipeline prior:\n%s", content)
	}
	if !strings.Contains(content, "- **AI Verdict:** _unclassified_") {
		t.Errorf("candidate file should state that no AI verdict exists yet:\n%s", content)
	}
	if _, err := os.Stat(filepath.Join(dir, FindingsDir)); !os.IsNotExist(err) {
		t.Errorf("%s/ must stay empty until the AI classifies (err=%v)", FindingsDir, err)
	}
}

func TestWriteReport_DocumentsBothDirs(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{
		ScanDir:    dir,
		ScanID:     "sc_test",
		ReportPath: filepath.Join(dir, ReportFile),
		SarifPath:  filepath.Join(dir, SarifFile),
	}
	if err := o.writeReport(candidatePackages(), IndexSummary{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(o.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{CandidatesDir + "/<vuln-type>/", FindingsDir + "/<vuln-type>/", "Dismissed"} {
		if !strings.Contains(content, want) {
			t.Errorf("report.md should explain %q:\n%s", want, content)
		}
	}
}
