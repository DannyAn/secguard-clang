//go:build !nosqlite

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// seedAuditScan seeds one completed scan (scan_stats + scan_runs + a finding) so
// `report --audit` can be exercised against it.
func seedAuditScan(t *testing.T, ctx context.Context, scanID string) string {
	t.Helper()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	if err := s.BeginScanRun(ctx, scanID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1, AIStageStatus: "done"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertFinding(ctx, &db.Finding{
		RuleID: "CWE-476", VulnType: "null-deref", Severity: "high", Confidence: 0.9,
		Status: "confirmed", FilePath: "a.c", LineNumber: 1, FunctionName: "f", ScanID: scanID,
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return dbPath
}

// A typo'd --scan-id must fail before writing any artifact: the bug it guards
// against is `report --audit` silently minting a full set of vuln_count=0
// reports for a scan id that never ran.
func TestReportAudit_UnknownScanIDFailsBeforeWriting(t *testing.T) {
	ctx := context.Background()
	const realID = "sc_2026-11-16_093712_91712c"
	dbPath := seedAuditScan(t, ctx, realID)

	outDir := filepath.Join(t.TempDir(), "typo")
	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", "sc_2026-11-16_093712_91772c", "--output-dir", outDir})
	})
	if exitCode == 0 {
		t.Fatalf("--audit with an unknown scan id must exit non-zero, got 0: %s", stdout)
	}
	if !strings.Contains(stdout, "unknown scan_id") {
		t.Errorf("error must name the unknown scan_id, got: %s", stdout)
	}
	if !strings.Contains(stdout, "did you mean") || !strings.Contains(stdout, realID) {
		t.Errorf("error must suggest the closest known scan id %q, got: %s", realID, stdout)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Errorf("unknown scan id must not create an output directory, but %s exists", outDir)
	}
}

// A scan id with no close neighbor still fails loudly (no hint, non-zero exit),
// and never fabricates artifacts.
func TestReportAudit_UnknownScanIDNoHintFails(t *testing.T) {
	ctx := context.Background()
	const realID = "sc_2026-11-16_093712_91712c"
	dbPath := seedAuditScan(t, ctx, realID)

	outDir := filepath.Join(t.TempDir(), "bogus")
	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", "sc_completely_different", "--output-dir", outDir})
	})
	if exitCode == 0 {
		t.Fatalf("--audit with an unknown scan id must exit non-zero, got 0: %s", stdout)
	}
	if !strings.Contains(stdout, "unknown scan_id") {
		t.Errorf("error must name the unknown scan_id, got: %s", stdout)
	}
	if strings.Contains(stdout, "did you mean") {
		t.Errorf("an unrelated id must not produce a spurious hint, got: %s", stdout)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Errorf("unknown scan id must not create an output directory, but %s exists", outDir)
	}
}
