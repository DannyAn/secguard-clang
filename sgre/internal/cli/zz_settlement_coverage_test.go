//go:build !nosqlite

package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestDeriveTypeCoverageIntervals(t *testing.T) {
	now := time.Now().UnixMilli()
	rows := []*db.SettlementStat{
		{VulnType: "null-deref", RangeStr: "1-40", Status: "done"},
		{VulnType: "null-deref", RangeStr: "41-80", Status: "done"},
	}
	cov := deriveTypeCoverage(rows, 100, now)
	if cov.Done {
		t.Fatalf("two settled ranges out of 100 candidates must not complete the type: %+v", cov)
	}
	if cov.CoveredCount != 80 {
		t.Errorf("covered = %d, want 80", cov.CoveredCount)
	}
	if len(cov.Uncovered) != 1 || cov.Uncovered[0] != "81-100" {
		t.Errorf("uncovered = %v, want [81-100]", cov.Uncovered)
	}

	rows = append(rows, &db.SettlementStat{VulnType: "null-deref", RangeStr: "81-100", Status: "done"})
	cov = deriveTypeCoverage(rows, 100, now)
	if !cov.Done {
		t.Fatalf("full 1-100 coverage must complete the type: %+v", cov)
	}

	rows = append(rows, &db.SettlementStat{VulnType: "null-deref", RangeStr: "1-40", Status: "dispatched", SubagentID: "holder-z", CreatedAt: now})
	cov = deriveTypeCoverage(rows, 100, now)
	if cov.Done {
		t.Fatalf("a live duplicate claim must block completion: %+v", cov)
	}
	if cov.ActiveClaims != 1 {
		t.Errorf("active claims = %d, want 1", cov.ActiveClaims)
	}

	rows = rows[:2]
	rows = append(rows, &db.SettlementStat{VulnType: "null-deref", RangeStr: "81-100", Status: "partial", NeedsContext: 2})
	cov = deriveTypeCoverage(rows, 100, now)
	if cov.Done {
		t.Fatalf("needs_context residue must block completion: %+v", cov)
	}
	if !cov.HasNeedsContext {
		t.Error("needs_context residue not reported")
	}
	if len(cov.Uncovered) != 1 || cov.Uncovered[0] != "81-100" {
		t.Errorf("a partial range must not count as covered: uncovered = %v", cov.Uncovered)
	}

	all := []*db.SettlementStat{{VulnType: "null-deref", RangeStr: "all", Status: "done"}}
	if cov := deriveTypeCoverage(all, 100, now); !cov.Done {
		t.Fatalf("range=all must cover the whole type: %+v", cov)
	}
}

// A single settled range out of many must NOT flip the type to done; the status
// projection must expose the exact uncovered interval for re-dispatch.
func TestPartialRangeSettlementDoesNotCompleteType(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := db.NewTestStore(t)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 200, FinalCount: 100}); err != nil {
		t.Fatal(err)
	}
	writeSettlementReport(t, root, "sub-a-report.json", `{
  "format_version": 1,
  "subagent_id": "sub-a",
  "scan_id": "sc_2026-01-01_000000_abcdef",
  "processed_types": [
    {"type": "null-deref", "range": "1-40", "cwe": "CWE-476", "written": 10, "dismissed": 30, "source_reads": 0, "evidence_opens": 0, "repo_greps": 0}
  ]
}`, time.Now())

	// The settled range 1-40 carries 40 terminal verdicts (10 confirmed + 30
	// dismissed), so remaining = 100 − 40 = 60 and uncovered = 41-100.
	for i := 0; i < 10; i++ {
		if _, err := store.UpsertFinding(ctx, &db.Finding{
			RuleID: "CWE-476", VulnType: "null-deref", Status: "confirmed", Severity: "high", FilePath: "a.c",
			LineNumber: 10 + i, Variable: "p", ScanID: scanID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 30; i++ {
		if _, err := store.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
			ScanID: scanID, VulnType: "null-deref", RuleID: "CWE-476", FilePath: "a.c",
			LineNumber: 30 + i, Variable: "q", Verdict: "dismissed", Reason: "guarded",
		}); err != nil {
			t.Fatal(err)
		}
	}

	res := listSubagentReports(filepath.Join(root, "test.db"), scanID)
	if err := persistSettlementReports(ctx, store, res); err != nil {
		t.Fatalf("persist settlement reports: %v", err)
	}

	statuses, err := store.ListPerTypeStatus(ctx, scanID, planner.CWEsForType)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range statuses {
		if st.AIStageStatus == "done" {
			t.Fatalf("one settled range out of 100 candidates must not mark the type done")
		}
	}
	enriched, err := enrichPerTypeStatus(ctx, store, scanID, statuses)
	if err != nil {
		t.Fatal(err)
	}
	var e *settlementEnriched
	for _, item := range enriched {
		if item.VulnType == "null-deref" {
			e = item
		}
	}
	if e == nil {
		t.Fatal("null-deref missing from enriched status")
	}
	if e.Remaining != 60 {
		t.Errorf("remaining = %d, want 60", e.Remaining)
	}
	if len(e.UncoveredRanges) != 1 || e.UncoveredRanges[0] != "41-100" {
		t.Errorf("uncovered_ranges = %v, want [41-100]", e.UncoveredRanges)
	}
	if len(e.AlreadyCoveredRanges) != 1 || e.AlreadyCoveredRanges[0] != "1-40" {
		t.Errorf("already_covered_ranges = %v, want [1-40]", e.AlreadyCoveredRanges)
	}
}

// A legacy worker that wrote its settlement as a fenced code block must still
// absorb (the bare-JSON contract applies to new writers; old in-flight reports
// must not stall their claims).
func TestFencedSettlementReportAbsorbs(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := db.NewTestStore(t)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	writeSettlementReport(t, root, "sub-a-report.json", "```json\n"+settlementReportBody+"\n```\n", time.Now())

	for i := 0; i < 2; i++ {
		if _, err := store.UpsertFinding(ctx, &db.Finding{
			RuleID: "CWE-476", VulnType: "null-deref", Status: "confirmed", Severity: "high", FilePath: "a.c",
			LineNumber: 10 + i, Variable: "p", ScanID: scanID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := store.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
			ScanID: scanID, VulnType: "null-deref", RuleID: "CWE-476", FilePath: "a.c",
			LineNumber: 20 + i, Variable: "q", Verdict: "dismissed", Reason: "guarded",
		}); err != nil {
			t.Fatal(err)
		}
	}

	res := listSubagentReports(filepath.Join(root, "test.db"), scanID)
	if len(res.Reports) != 1 || !res.Reports[0].Valid {
		t.Fatalf("fenced report must parse as valid: %+v", res.Reports)
	}
	if err := persistSettlementReports(ctx, store, res); err != nil {
		t.Fatalf("persist fenced report: %v", err)
	}
	statuses, err := store.ListPerTypeStatus(ctx, scanID, planner.CWEsForType)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range statuses {
		if st.AIStageStatus != "done" {
			t.Errorf("ai_stage_status = %q, want done (fenced report absorbed)", st.AIStageStatus)
		}
	}
}

// The audit gate: a type with candidates whose AI stage is unfinished blocks the
// terminal artifacts by default, and --allow-partial emits an explicitly
// labelled partial report.
func TestReportAuditGateRefusesUnfinishedTypes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	const scanID = "sc_2026-01-01_000000_eeeeee"
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 10, FinalCount: 7}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	stdout, _, code := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", scanID})
	})
	if code == 0 {
		t.Fatalf("audit must refuse unfinished types by default: %s", stdout)
	}
	if !strings.Contains(stdout, `"incomplete"`) || !strings.Contains(stdout, "--allow-partial") {
		t.Errorf("refusal must name the partial escape hatch: %s", stdout)
	}

	stdout, _, code = captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", scanID, "--allow-partial"})
	})
	if code != 0 {
		t.Fatalf("--allow-partial audit failed: %s", stdout)
	}
	var out struct {
		Partial      bool `json:"partial"`
		Unclassified int  `json:"unclassified_candidates"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("partial audit output is not JSON: %s", stdout)
	}
	if !out.Partial {
		t.Error("partial audit must set partial:true")
	}
	if out.Unclassified != 7 {
		t.Errorf("unclassified = %d, want 7 (never classified, not dismissed)", out.Unclassified)
	}
}
