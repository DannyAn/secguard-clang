package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAuditReport_IncludesAIValueSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-report.md")
	audits := []vulnAuditEntry{
		{VulnType: "buffer-overflow", SeedCount: 12, FinalCount: 11, Confirmed: 8, Suspected: 1, Dismissed: 2},
		{VulnType: "out-of-bounds", SeedCount: 1, FinalCount: 1, Confirmed: 0, Suspected: 0, Dismissed: 0},
	}

	if err := writeAuditReport(path, "test-scan", audits); err != nil {
		t.Fatalf("writeAuditReport failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit report: %v", err)
	}
	out := string(data)

	checks := []string{
		"## AI Value Summary",
		"| Raw evidence seeds | 13 |",
		"| Converged candidates (after pipeline filters) | 12 |",
		"| Candidates classified by AI | 11 |",
		"| Candidates without AI classification | 1 |",
		"| AI confirmed (actionable, with fix suggestion) | 8 |",
		"| AI suspected (needs human decision) | 1 |",
		"| AI dismissed (false positives, evidence recorded) | 2 |",
		"| Actionable findings for human review | 9 |",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("audit report missing %q", check)
		}
	}
}
