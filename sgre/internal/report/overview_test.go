package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func demoOverview() ScanOverview {
	return ScanOverview{
		ScanID:           "sc_2026-09-10_225407_56ef13",
		TargetPath:       "/repo/redis",
		StartedAt:        time.Date(2026, 9, 10, 22, 54, 7, 0, time.UTC),
		DurationMs:       12345,
		AIDurationMs:     3200000,
		FilesIndexed:     218,
		FunctionsIndexed: 5811,
		FunctionsInIndex: 5811,
		FilesInIndex:     218,
		HasScanMetrics:   true,
		LinesOfCode:      320450,
		RawSeeds:         2920,
		Candidates:       49,
		AutoConfirmed:    3,
		TypesScanned:     20,
	}
}

// A reader must be able to answer "how big was this scan" and "how many issues,
// confirmed vs suspected" from report.md alone — the gap that made the console
// richer than the artifact.
func TestWriteReportFromFindings_ScaleAndAggregate(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, ReportFile)

	findings := verdictFindings()
	findings = append(findings, &db.Finding{
		RuleID: "CWE-252", Severity: "high", Status: db.StatusAutoConfirmed,
		FilePath: "src/auto.c", LineNumber: 3, FunctionName: "auto_confirmed",
		Summary: "malloc return unchecked",
	})

	if err := WriteReportFromFindings(reportPath, "", findings, demoOverview()); err != nil {
		t.Fatalf("WriteReportFromFindings: %v", err)
	}
	content := string(mustReadFile(t, reportPath))

	for _, want := range []string{
		"## Scan Overview",
		"| Scan ID | `sc_2026-09-10_225407_56ef13` |",
		"| Target | `/repo/redis` |",
		"| Scan time | 2026-09-10 22:54:07 |",
		"| Automated analysis | 12.3 s (index + graph + detectors + convergence + auto-confirm) |",
		"| AI classification | 53 m 20 s |",
		"| Codebase scale | 218 files / 5811 functions / 320450 lines |",
		"| Vulnerability types scanned | 20 |",
		"## Result Summary",
		"| Files scanned | 218 |",
		"| Functions scanned | 5811 |",
		"| Lines of code | 320450 |",
		"| Raw evidence seeds | 2920 |",
		"| Converged candidates | 49 |",
		"| Confirmed findings | 3 |",
		"| — proved by the pipeline (auto-confirmed, no AI review) | 1 |",
		"| — classified by the AI | 2 |",
		"| Actionable findings (confirmed + suspected) | 4 |",
		"### Findings by Severity",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("report.md missing %q\n---\n%s", want, content)
		}
	}

	// The headline and the table are rendered from the SAME derived figures: the
	// auto-confirmed row must be counted inside "Confirmed findings", never in
	// addition to it.
	if !strings.Contains(content, "**This scan reported 4 actionable issues: 3 confirmed, 1 suspected. Of the confirmed ones, 1 auto-confirmed by the pipeline (no AI review) and 2 classified by the AI.**") {
		t.Errorf("headline should state the aggregate with its auto-confirmed split:\n%s", content)
	}
}

// The candidate-stage report is pre-classification: it must state the scan scale
// and how much of the convergence output still awaits the AI, and it must not
// borrow verdict language.
func TestWriteReport_CandidateStageStatesScaleAndRemaining(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{
		ScanDir:    dir,
		ScanID:     "sc_test",
		ReportPath: filepath.Join(dir, ReportFile),
	}
	summary := IndexSummary{
		FilesIndexed:     218,
		FunctionsIndexed: 5811,
		FunctionsInIndex: 5811,
		LinesOfCode:      320450,
		TargetPath:       "/repo/redis",
		SeedCount:        2920,
		AutoConfirmed:    3,
		DurationMs:       12345,
		TypesScanned:     20,
	}
	if err := o.writeReport(candidatePackages(), summary); err != nil {
		t.Fatal(err)
	}
	content := string(mustReadFile(t, o.ReportPath))

	for _, want := range []string{
		"| Target | `/repo/redis` |",
		"| Codebase scale | 218 files / 5811 functions / 320450 lines |",
		"| Raw evidence seeds | 2920 |",
		"| Converged candidates | 1 |",
		"| Auto-confirmed by pipeline | 3 |",
		"**0 converged candidates are awaiting AI classification (3 already proved and auto-confirmed by the pipeline).**",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("candidate report.md missing %q\n---\n%s", want, content)
		}
	}
	if strings.Contains(content, "Confirmed findings") {
		t.Errorf("candidate-stage report must not use verdict language:\n%s", content)
	}
}

// An unknown scan scale is reported as "n/a" — printing 0 would read as "this
// codebase has no files", the opposite of "we have no metrics row for it".
func TestScanOverview_UnknownScaleIsNotZero(t *testing.T) {
	ov := ScanOverview{}
	if got := ov.ScaleText(); got != "n/a" {
		t.Errorf("ScaleText() = %q, want n/a", got)
	}
	if md := ov.MetadataMarkdown(); strings.Contains(md, "| Files scanned | 0 |") {
		t.Errorf("unknown scale must be omitted, not printed as 0:\n%s", md)
	}
}

func TestScanOverview_SummaryFieldsAreSelfConsistent(t *testing.T) {
	ov := demoOverview()
	ov.AIConfirmed = 2
	ov.AISuspected = 5
	ov.AIDismissed = 7
	ov.Unclassified = 1

	fields := ov.SummaryFields()
	confirmed := fields["confirmed_total"].(int)
	suspected := fields["suspected_total"].(int)
	actionable := fields["actionable_total"].(int)

	if confirmed != ov.AutoConfirmed+ov.AIConfirmed {
		t.Errorf("confirmed_total = %d, want auto(%d) + ai(%d)", confirmed, ov.AutoConfirmed, ov.AIConfirmed)
	}
	if actionable != confirmed+suspected {
		t.Errorf("actionable_total = %d, want confirmed(%d) + suspected(%d)", actionable, confirmed, suspected)
	}
	// The machine-readable aggregate is the console's source of truth for the
	// headline; it must be present so the orchestrator never re-derives it.
	if fields["headline"] == "" {
		t.Error("summary must carry a headline for the console to echo")
	}
}

func TestScanOverview_SeverityBreakdownCountsAutoConfirmed(t *testing.T) {
	findings := []*db.Finding{
		{RuleID: "CWE-476", Severity: "high", Status: db.StatusAutoConfirmed},
		{RuleID: "CWE-476", Severity: "high", Status: "confirmed"},
		{RuleID: "CWE-787", Severity: "medium", Status: "suspected"},
		{RuleID: "CWE-787", Severity: "low", Status: "dismissed"},
	}
	counts := CountSeverities(findings)
	if counts["high"].Confirmed != 2 {
		t.Errorf("auto-confirmed must count as confirmed by severity: %+v", counts["high"])
	}
	if counts["medium"].Suspected != 1 {
		t.Errorf("suspected must be counted per severity: %+v", counts["medium"])
	}
	if _, ok := counts["low"]; ok {
		t.Errorf("dismissed findings must not appear in the severity breakdown: %+v", counts)
	}

	md := severityMarkdown(counts)
	if !strings.Contains(md, "| **TOTAL** | **2** | **1** | **3** |") {
		t.Errorf("severity table should total every actionable finding:\n%s", md)
	}
}

// A scan with no `scan_runs` row (a pre-metrics scan, or a review run) must
// report the whole-index figures it does have — never "0 files / 0 functions
// scanned", which reads as an empty codebase rather than "not measured".
func TestScanOverview_NoMetricsRowFallsBackToIndexLabels(t *testing.T) {
	ov := ScanOverview{
		ScanID:           "diff_abc_123",
		FilesInIndex:     218,
		FunctionsInIndex: 5811,
		LinesOfCode:      320450,
		Candidates:       2,
	}
	md := ov.MetadataMarkdown() + ov.CandidateMarkdown()

	if strings.Contains(md, "| Files scanned |") || strings.Contains(md, "| Functions scanned |") {
		t.Errorf("without a metrics row the 'scanned' rows must not be printed (they would read as 0):\n%s", md)
	}
	for _, want := range []string{
		"| Files in index | 218 |",
		"| Functions in index | 5811 |",
		"| Lines of code | 320450 |",
		"| Codebase scale | 218 files (in index) / 5811 functions (in index) / 320450 lines |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q\n---\n%s", want, md)
		}
	}
	if fields := ov.SummaryFields(); fields["scan_metrics_available"] != false {
		t.Errorf("summary must admit the metrics row is missing: %+v", fields)
	}
}

func TestScanOverview_NoFindingsHeadlineStatesSo(t *testing.T) {
	ov := ScanOverview{ScanID: "sc_x", FilesIndexed: 10, FunctionsIndexed: 20, Candidates: 4, AIDismissed: 4}
	if got := ov.Headline(); !strings.Contains(got, "no actionable issue") {
		t.Errorf("a scan with only dismissed verdicts must say so plainly, got %q", got)
	}
	if !strings.Contains(ov.VerdictMarkdown(), "| Dismissed (false positives) | 4 |") {
		t.Errorf("dismissed count must still be reported:\n%s", ov.VerdictMarkdown())
	}
}
