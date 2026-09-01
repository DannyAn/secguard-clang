package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
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

func verdictFindings() []*db.Finding {
	return []*db.Finding{
		{
			RuleID: "CWE-787", Severity: "high", Confidence: 0.9,
			Status: "confirmed", ReviewStatus: "",
			FilePath: "src/overflow.c", LineNumber: 42, FunctionName: "vuln_write",
			Summary: "栈缓冲区溢出", Reasoning: "memcpy 长度超过缓冲区容量",
		},
		{
			RuleID: "CWE-787", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "suspected-kept",
			FilePath: "src/maybe.c", LineNumber: 17, FunctionName: "risky_copy",
			Summary: "可能溢出", Reasoning: "长度依赖外部输入",
		},
		{
			RuleID: "CWE-787", Severity: "low", Confidence: 0.3,
			Status: "suspected", ReviewStatus: "dismissed",
			FilePath: "src/false.c", LineNumber: 8, FunctionName: "safe_check",
			Summary: "误报", Reasoning: "已有边界检查",
		},
		{
			RuleID: "CWE-416", Severity: "high", Confidence: 0.85,
			Status: "confirmed", ReviewStatus: "",
			FilePath: "src/uaf.c", LineNumber: 99, FunctionName: "dangling",
			Summary: "释放后使用", Reasoning: "free 后仍访问指针",
		},
	}
}

// WriteReportFromFindings must show only actionable verdicts (confirmed +
// suspected) and must never include dismissed entries — mirroring result.sarif
// and the findings/ directory.
func TestWriteReportFromFindings_ExcludesDismissed(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", verdictFindings()); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if strings.Contains(content, "safe_check") {
		t.Errorf("dismissed finding must not appear in report.md:\n%s", content)
	}
	if strings.Contains(content, "误报") {
		t.Errorf("dismissed finding summary must not appear in report.md:\n%s", content)
	}
}

func TestWriteReportFromFindings_ShowsActionable(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", verdictFindings()); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))

	for _, want := range []string{"vuln_write", "risky_copy", "dangling"} {
		if !strings.Contains(content, want) {
			t.Errorf("actionable finding %q should appear in report.md:\n%s", want, content)
		}
	}
	if !strings.Contains(content, "AI-classified findings") {
		t.Errorf("report should declare it shows AI-classified findings:\n%s", content)
	}
	if !strings.Contains(content, "| Confirmed findings | 2 |") {
		t.Errorf("summary should count 2 confirmed:\n%s", content)
	}
	if !strings.Contains(content, "| Suspected findings | 1 |") {
		t.Errorf("summary should count 1 suspected (dismissed excluded):\n%s", content)
	}
	if !strings.Contains(content, "| Dismissed (false positives) | 1 |") {
		t.Errorf("summary should count 1 dismissed:\n%s", content)
	}
}

// A plain suspected finding (no review_status) is a final first-pass verdict —
// A5 has been folded into A4 — so it appears in the final report exactly like a
// suspected-kept finding.
func TestWriteReportFromFindings_IncludesPlainSuspected(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	findings := []*db.Finding{
		{
			RuleID: "CWE-787", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "",
			FilePath: "src/maybe.c", LineNumber: 17, FunctionName: "risky_copy",
			Summary: "可能溢出", Reasoning: "长度依赖外部输入",
		},
		{
			RuleID: "CWE-787", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "suspected-kept",
			FilePath: "src/kept.c", LineNumber: 20, FunctionName: "kept_risky",
			Summary: "A5 保留的疑似", Reasoning: "外部输入无界",
		},
	}

	if err := WriteReportFromFindings(reportPath, "", findings); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))

	if !strings.Contains(content, "risky_copy") {
		t.Errorf("plain suspected finding should appear in report.md:\n%s", content)
	}
	if !strings.Contains(content, "kept_risky") {
		t.Errorf("suspected-kept finding should appear in report.md:\n%s", content)
	}
	if !strings.Contains(content, "| Suspected findings | 2 |") {
		t.Errorf("summary should count 2 suspected (plain + suspected-kept):\n%s", content)
	}
}

func TestWriteReportFromFindings_GroupsByVulnType(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", verdictFindings()); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))

	if !strings.Contains(content, "## buffer-overflow") {
		t.Errorf("should have a buffer-overflow section:\n%s", content)
	}
	if !strings.Contains(content, "## use-after-free") {
		t.Errorf("should have a use-after-free section:\n%s", content)
	}
}

func TestWriteReportFromFindings_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	if err := WriteReportFromFindings(reportPath, "", nil); err != nil {
		t.Fatalf("WriteReportFromFindings with nil findings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))
	if !strings.Contains(content, "| Confirmed findings | 0 |") {
		t.Errorf("empty findings should produce zero counts:\n%s", content)
	}
}

func TestWriteReportFromFindings_RespectsReviewStatus(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	findings := []*db.Finding{
		{
			RuleID: "CWE-476", Severity: "high", Confidence: 0.8,
			Status: "confirmed", ReviewStatus: "dismissed",
			FilePath: "src/a.c", LineNumber: 5, FunctionName: "f",
			Summary: "A5 降级为误报",
		},
	}

	if err := WriteReportFromFindings(reportPath, "", findings); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}

	content := string(mustReadFile(t, reportPath))
	if strings.Contains(content, "| Confirmed findings | 1 |") {
		t.Errorf("A5 review_status=dismissed must override first-pass confirmed:\n%s", content)
	}
	if !strings.Contains(content, "| Dismissed (false positives) | 1 |") {
		t.Errorf("dismissed count should reflect A5 override:\n%s", content)
	}
}

// The per-type _index.md must name the EXACT candidate evidence filename in its
// Evidence column, so a subagent can open a suspected/possible candidate's
// Code Context without guessing the <NNN>_<short-file>_<line>.md name.
func TestWriteTypeIndex_IncludesEvidenceFilename(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: "/repo"}
	if err := o.writeCandidates(candidatePackages()); err != nil {
		t.Fatal(err)
	}

	idxPath := filepath.Join(dir, CandidatesDir, "null-deref", TypeIndexFile)
	content := string(mustReadFile(t, idxPath))

	for _, want := range []string{"| Evidence |", "001_src_a_c_13.md"} {
		if !strings.Contains(content, want) {
			t.Errorf("_index.md missing %q:\n%s", want, content)
		}
	}
	// The candidate file named by Evidence must actually exist on disk.
	if _, err := os.Stat(filepath.Join(dir, CandidatesDir, "null-deref", "001_src_a_c_13.md")); err != nil {
		t.Errorf("evidence file named by _index.md does not exist: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
