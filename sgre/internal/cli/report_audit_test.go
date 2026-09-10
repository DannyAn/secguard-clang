package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/report"
)

func TestWriteAuditReport_IncludesAIValueSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-report.md")
	audits := []vulnAuditEntry{
		{VulnType: "buffer-overflow", SeedCount: 12, FinalCount: 11, AutoConfirmed: 3, Confirmed: 8, Suspected: 1, Dismissed: 2},
		{VulnType: "out-of-bounds", SeedCount: 1, FinalCount: 1, Confirmed: 0, Suspected: 0, Dismissed: 0},
	}
	overview := report.ScanOverview{
		ScanID: "test-scan", HasScanMetrics: true, FilesIndexed: 26, FunctionsIndexed: 173,
		FilesInIndex: 26, LinesOfCode: 9001,
		TargetPath: "/repo/zlib", RawSeeds: 13, Candidates: 12, AutoConfirmed: 3,
		AIConfirmed: 8, AISuspected: 1, AIDismissed: 2, TypesScanned: 20, TypesWithFindings: 1,
	}

	if err := writeAuditReport(path, "test-scan", audits, overview); err != nil {
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
		"| Auto-confirmed by pipeline (no AI review) | 3 |",
		"| Candidates needing AI review (suspected/possible) | 12 |",
		"| Candidates classified by AI | 11 |",
		"| Candidates without AI classification | 1 |",
		"| AI confirmed (actionable, with fix suggestion) | 8 |",
		"| AI suspected (needs human decision) | 1 |",
		"| AI dismissed (false positives, evidence recorded) | 2 |",
		"| Actionable findings for human review | 9 |",
		// The audit report must open with the same scan-scale + headline block
		// report.md shows, so the two artifacts answer "how big was this scan"
		// and "what was the bottom line" identically.
		"## Scan Overview",
		"| Codebase scale | 26 files / 173 functions / 9001 lines |",
		"| Target | `/repo/zlib` |",
		"**This scan reported 12 actionable issues: 11 confirmed, 1 suspected. Of the confirmed ones, 3 auto-confirmed by the pipeline (no AI review) and 8 classified by the AI.**",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("audit report missing %q\n---\n%s", check, out)
		}
	}
}

// A scan's report header must name the directory that was actually scanned.
// scan_runs stores no target path, and the project root the DB lives in is
// often a PARENT of the scanned subtree (`secguard scan src/`), so the indexed
// file paths are the only honest source.
func TestIndexPathRoot(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{"no files", nil, ""},
		{"single file", []string{"/repo/src/a.c"}, "/repo/src"},
		{"siblings", []string{"/repo/src/a.c", "/repo/src/b.c"}, "/repo/src"},
		{"common parent", []string{"/repo/src/a.c", "/repo/lib/b.c"}, "/repo"},
		{"deepest common", []string{"/repo/a/x/1.c", "/repo/a/y/2.c", "/repo/a/z.c"}, "/repo/a"},
	}
	for _, tc := range cases {
		files := make([]*db.File, 0, len(tc.paths))
		for _, p := range tc.paths {
			files = append(files, &db.File{Path: p})
		}
		if got := indexPathRoot(files); got != tc.want {
			t.Errorf("%s: indexPathRoot = %q, want %q", tc.name, got, tc.want)
		}
	}
}
