package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildScanSummary_Header(t *testing.T) {
	data := SummaryData{
		ScanID:           "test-scan-id",
		TargetPath:       "/abs/path/to/src",
		ScanDir:          "/abs/path/to/scans/test-scan-id",
		TotalCandidates:  15,
		FilesIndexed:     42,
		FunctionsIndexed: 128,
		TypeBreakdown:    []TypeBreakdownEntry{{Type: "null-deref", CWE: "CWE-476", Count: 5}},
		ReportPath:       "/abs/report.md",
		SarifPath:        "/abs/sarif.sarif",
		LatestPath:       "/abs/latest",
	}
	out := BuildScanSummary(data)

	checks := []string{
		"## SecGuard Scan Summary",
		"| Scan ID | test-scan-id |",
		"| Target | /abs/path/to/src |",
		"| Scan Dir | /abs/path/to/scans/test-scan-id |",
		"| Total Candidates | 15 |",
		"| Files Indexed | 42 |",
		"| Functions Indexed | 128 |",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("expected output to contain %q", check)
		}
	}
}

func TestBuildScanSummary_TypeBreakdown(t *testing.T) {
	data := SummaryData{
		ScanID: "test",
		TypeBreakdown: []TypeBreakdownEntry{
			{Type: "null-deref", CWE: "CWE-476", Count: 5},
			{Type: "buffer-overflow", CWE: "CWE-787", Count: 3},
			{Type: "memory-leak", CWE: "CWE-401", Count: 7},
		},
		TotalCandidates: 15,
	}
	out := BuildScanSummary(data)

	checks := []string{
		"### Candidates by Type",
		"| Type | CWE | Count |",
		"|------|-----|-------|",
		"| null-deref | CWE-476 | 5 |",
		"| buffer-overflow | CWE-787 | 3 |",
		"| memory-leak | CWE-401 | 7 |",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("expected output to contain %q", check)
		}
	}
}

func TestBuildScanSummary_OmitsZeroCount(t *testing.T) {
	data := SummaryData{
		ScanID:          "test",
		TotalCandidates: 0,
		TypeBreakdown:   nil,
	}
	out := BuildScanSummary(data)

	if !strings.Contains(out, "No issues found.") {
		t.Error("expected 'No issues found.' message for zero candidates")
	}
	if strings.Contains(out, "| Type | CWE | Count |") {
		t.Error("should not contain type breakdown table for zero candidates")
	}
}

func TestBuildScanSummary_OutputFiles(t *testing.T) {
	data := SummaryData{
		ScanID:     "test",
		ReportPath: "/path/to/report.md",
		SarifPath:  "/path/to/sarif.sarif",
		LatestPath: "/path/to/latest",
	}
	out := BuildScanSummary(data)

	checks := []string{
		"### Output Files",
		"- Report: /path/to/report.md",
		"- SARIF: /path/to/sarif.sarif",
		"- Latest: /path/to/latest",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("expected output to contain %q", check)
		}
	}
}

func TestBuildScanSummary_Deterministic(t *testing.T) {
	data := SummaryData{
		ScanID:          "test",
		TotalCandidates: 5,
		TypeBreakdown:   []TypeBreakdownEntry{{Type: "null-deref", CWE: "CWE-476", Count: 5}},
	}
	out1 := BuildScanSummary(data)
	out2 := BuildScanSummary(data)
	if out1 != out2 {
		t.Error("BuildScanSummary is not deterministic — same input produced different output")
	}
}

func TestBuildScanSummary_LineCount(t *testing.T) {
	data := SummaryData{
		ScanID:          "test",
		TotalCandidates: 100,
		TypeBreakdown:   make([]TypeBreakdownEntry, 14),
	}
	for i := range data.TypeBreakdown {
		data.TypeBreakdown[i] = TypeBreakdownEntry{Type: "type", CWE: "CWE-000", Count: 1}
	}
	out := BuildScanSummary(data)
	lineCount := strings.Count(out, "\n") + 1
	if lineCount > 50 {
		t.Errorf("summary output exceeds 50 lines: %d", lineCount)
	}
}

func TestPrintScanSummary_WritesToWriter(t *testing.T) {
	var buf bytes.Buffer
	data := SummaryData{
		ScanID:          "test",
		TotalCandidates: 5,
		TypeBreakdown:   []TypeBreakdownEntry{{Type: "null-deref", CWE: "CWE-476", Count: 5}},
	}
	PrintScanSummary(&buf, data)
	if !strings.Contains(buf.String(), "## SecGuard Scan Summary") {
		t.Error("writer does not contain summary table")
	}
}

func TestPrintScanSummary_InvalidMetadata(t *testing.T) {
	var buf bytes.Buffer
	PrintScanSummary(&buf, SummaryData{})
	if !strings.Contains(buf.String(), "warning: summary generation skipped") {
		t.Error("expected warning for invalid metadata")
	}
}

func TestVulnToCWE(t *testing.T) {
	tests := []struct {
		vulnType string
		expected string
	}{
		{"null-deref", "CWE-476"},
		{"buffer-overflow", "CWE-787"},
		{"crypto-misuse", "CWE-327"},
		{"unknown-type", "CWE-Other"},
		{"", "CWE-Other"},
	}
	for _, tt := range tests {
		if got := VulnToCWE(tt.vulnType); got != tt.expected {
			t.Errorf("VulnToCWE(%q) = %q, want %q", tt.vulnType, got, tt.expected)
		}
	}
}
