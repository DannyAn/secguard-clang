//go:build !nosqlite

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// seedListFindings opens a fresh DB and writes one finding per scan, so --list
// can be exercised against multiple scans sharing a single database.
func seedListFindings(t *testing.T, ctx context.Context) (dbPath, scan1, scan2 string) {
	t.Helper()
	root := t.TempDir()
	dbPath = filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	scan1 = "sc_2026-01-01_000000_aaaaaa"
	scan2 = "sc_2026-01-02_000000_bbbbbb"
	for _, scanID := range []string{scan1, scan2} {
		if _, err := s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.UpsertFinding(ctx, &db.Finding{
		RuleID: "CWE-476", VulnType: "null-deref", Severity: "high", Confidence: 0.9,
		Status: "confirmed", FilePath: "a.c", LineNumber: 1, FunctionName: "f", ScanID: scan1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertFinding(ctx, &db.Finding{
		RuleID: "CWE-476", VulnType: "null-deref", Severity: "high", Confidence: 0.9,
		Status: "confirmed", FilePath: "b.c", LineNumber: 2, FunctionName: "g", ScanID: scan2,
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return dbPath, scan1, scan2
}

func TestReportList_ScanIDFilterAndShape(t *testing.T) {
	ctx := context.Background()
	dbPath, scan1, _ := seedListFindings(t, ctx)

	// --list --scan-id filters to one scan and returns the stable envelope.
	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--list", "--scan-id", scan1})
	})
	if exitCode != 0 {
		t.Fatalf("--list --scan-id failed: %s", stdout)
	}
	var env struct {
		Count    int              `json:"count"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("--list must return an object envelope, got: %s", stdout)
	}
	if env.Count != 1 || len(env.Findings) != 1 {
		t.Fatalf("--list --scan-id should return exactly 1 finding, got count=%d findings=%d", env.Count, len(env.Findings))
	}
	if env.Findings[0]["scan_id"] != scan1 {
		t.Errorf("--list --scan-id leaked another scan's finding: %+v", env.Findings[0])
	}

	// A nonexistent scan-id returns an empty envelope (not every scan's rows).
	stdout, _, exitCode = captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--list", "--scan-id", "sc_DOES_NOT_EXIST"})
	})
	if exitCode != 0 {
		t.Fatalf("--list --scan-id (unknown) failed: %s", stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("--list must return an object envelope, got: %s", stdout)
	}
	if env.Count != 0 || len(env.Findings) != 0 {
		t.Errorf("unknown --scan-id should be empty, got count=%d", env.Count)
	}
}

func TestReportList_EffectiveStatusField(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	const scanID = "sc_2026-01-01_000000_cccccc"
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "memory-leak", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	// An auto-confirmed finding that Step 5.5 re-review dismissed: raw status is
	// still auto-confirmed, but EffectiveStatus is dismissed.
	if _, err := s.UpsertFinding(ctx, &db.Finding{
		RuleID: "CWE-401", VulnType: "memory-leak", Severity: "high", Confidence: 1.0,
		Status: db.StatusAutoConfirmed, ReviewStatus: "dismissed",
		FilePath: "a.c", LineNumber: 1, FunctionName: "f", ScanID: scanID,
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--list", "--status", "dismissed"})
	})
	if exitCode != 0 {
		t.Fatalf("--list --status dismissed failed: %s", stdout)
	}
	var env struct {
		Count    int              `json:"count"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("--list must return an object envelope, got: %s", stdout)
	}
	if env.Count != 1 {
		t.Fatalf("--status dismissed should match the reviewed-out finding, got count=%d", env.Count)
	}
	row := env.Findings[0]
	if row["status"] != db.StatusAutoConfirmed {
		t.Errorf("raw status field should stay auto-confirmed, got %v", row["status"])
	}
	if row["effective_status"] != "dismissed" {
		t.Errorf("effective_status field = %v, want dismissed", row["effective_status"])
	}
}

func TestReportAudit_WritesPipelineDismissedNotAIDismissed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	const scanID = "sc_2026-01-01_000000_dddddd"
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
		ScanID: scanID, VulnType: "null-deref", FilePath: "a.c", LineNumber: 3, FunctionName: "f", Verdict: "dismissed", Reason: "guarded",
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	outDir := filepath.Join(root, "scan")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", scanID, "--output-dir", outDir, "--allow-partial"})
	})
	if exitCode != 0 {
		t.Fatalf("--audit failed: %s", stdout)
	}

	if _, err := os.Stat(filepath.Join(outDir, "pipeline-dismissed.json")); err != nil {
		t.Errorf("audit must write pipeline-dismissed.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "ai-dismissed.json")); !os.IsNotExist(err) {
		t.Errorf("audit must not write ai-dismissed.json (reserved for the orchestrator)")
	}
}
