//go:build !nosqlite

package cli

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestNormalizeSettlementRange(t *testing.T) {
	cases := map[string]string{"": "all", "  ": "all", "all": "all", "1-69": "1-69"}
	for in, want := range cases {
		if got := normalizeSettlementRange(in); got != want {
			t.Errorf("normalizeSettlementRange(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSuggestedBatchSizeAndBatches(t *testing.T) {
	if got := suggestedBatchSize(0.63); got != 19 {
		t.Errorf("suggestedBatchSize(0.63) = %d, want 19 (floor(12/0.63))", got)
	}
	if got := suggestedBatchSize(1.0); got != 12 {
		t.Errorf("suggestedBatchSize(1.0) = %d, want 12", got)
	}
	if got := suggestedBatchSize(20.0); got != 1 {
		t.Errorf("suggestedBatchSize(20.0) = %d, want 1 (clamped)", got)
	}
	if got := suggestedBatches(560, 19); got != 30 {
		t.Errorf("suggestedBatches(560, 19) = %d, want 30", got)
	}
	if got := suggestedBatches(0, 19); got != 0 {
		t.Errorf("suggestedBatches(0, 19) = %d, want 0", got)
	}
}

func TestSettlementAggregate(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	// null-deref: 12 opens across 19 classified candidates = 0.6316...
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_prev", VulnType: "null-deref", RangeStr: "all", SubagentID: "a",
		Written: 3, Dismissed: 16, EvidenceOpens: 12,
	}); err != nil {
		t.Fatal(err)
	}

	agg := settlementAggregate(ctx, store, "null-deref")
	if agg.sample != 1 {
		t.Errorf("sample = %d, want 1", agg.sample)
	}
	if math.Abs(agg.rType-12.0/19.0) > 1e-9 {
		t.Errorf("rType = %f, want %f", agg.rType, 12.0/19.0)
	}
	if agg.avgWallMS != 0 {
		t.Errorf("avgWallMS = %d, want 0 (no wall_ms recorded)", agg.avgWallMS)
	}

	// No history → fallback 0.30, sample 0.
	empty := settlementAggregate(ctx, store, "divide-by-zero")
	if empty.rType != settlementRTypeFallback || empty.sample != 0 {
		t.Errorf("empty aggregate = %+v, want fallback/sample0", empty)
	}
}

func TestEnrichPerTypeStatusAlreadyCovered(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: "sc_test", VulnType: "uninit", SeedCount: 90, FinalCount: 90}); err != nil {
		t.Fatal(err)
	}
	// this scan already settled range 1-50
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_test", VulnType: "uninit", RangeStr: "1-50", SubagentID: "b",
		Written: 0, Dismissed: 50, EvidenceOpens: 0,
	}); err != nil {
		t.Fatal(err)
	}

	statuses, err := store.ListPerTypeStatus(ctx, "sc_test", func(string) []string { return []string{"CWE-457"} })
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := enrichPerTypeStatus(ctx, store, "sc_test", statuses)
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched, got %d", len(enriched))
	}
	e := enriched[0]
	if len(e.AlreadyCoveredRanges) != 1 || e.AlreadyCoveredRanges[0] != "1-50" {
		t.Errorf("already_covered_ranges = %v, want [1-50]", e.AlreadyCoveredRanges)
	}
	if e.VulnType != "uninit" || e.CandidateCount != 90 {
		t.Errorf("base status fields lost: %+v", e.PerTypeStatus)
	}
}

// TestEnrichPerTypeStatusClaimInFlight pins the pre-dispatch placeholder's
// read side (#217): a fresh `dispatched` claim is reported under
// in_flight_ranges (not already_covered_ranges), so a second planner skips it;
// a stale claim is omitted from both, so the next planning pass may reclaim it.
func TestEnrichPerTypeStatusClaimInFlight(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: "sc_test", VulnType: "buffer-overflow", SeedCount: 120, FinalCount: 120}); err != nil {
		t.Fatal(err)
	}
	nowSec := time.Now().Unix()
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_test", VulnType: "buffer-overflow", RangeStr: "1-20", SubagentID: "live-holder",
		Status: "dispatched", CreatedAt: nowSec,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_test", VulnType: "buffer-overflow", RangeStr: "21-40", SubagentID: "dead-holder",
		Status: "dispatched", CreatedAt: nowSec - int64(settlementClaimTTL/time.Second) - 60,
	}); err != nil {
		t.Fatal(err)
	}

	statuses, err := store.ListPerTypeStatus(ctx, "sc_test", func(string) []string { return []string{"CWE-787"} })
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := enrichPerTypeStatus(ctx, store, "sc_test", statuses)
	if err != nil {
		t.Fatal(err)
	}
	e := enriched[0]
	if len(e.AlreadyCoveredRanges) != 0 {
		t.Errorf("a claim is not coverage: already_covered_ranges = %v", e.AlreadyCoveredRanges)
	}
	if len(e.InFlightRanges) != 1 || e.InFlightRanges[0].Range != "1-20" || e.InFlightRanges[0].Holder != "live-holder" {
		t.Errorf("in_flight_ranges = %+v, want only the fresh 1-20 claim", e.InFlightRanges)
	}
}

func TestStatusCmdClaim(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 40, FinalCount: 40}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	claim := func(holder string, extra ...string) map[string]any {
		args := append([]string{"--db", dbPath, "--scan-id", scanID, "--claim-type", "null-deref", "--claim-range", "1-20", "--claim-holder", holder}, extra...)
		stdout, _, code := captureOutput(func() int { return runStatusCmd(ctx, args) })
		if code != 0 {
			t.Fatalf("claim %s failed: %s", holder, stdout)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("claim output is not JSON: %s", stdout)
		}
		return out
	}

	first := claim("holder-a")
	if first["claimed"] != true || first["reason"] != "new" {
		t.Fatalf("first claim = %+v, want claimed/new", first)
	}
	second := claim("holder-b")
	if second["claimed"] != false || second["reason"] != "held" || second["holder"] != "holder-a" {
		t.Fatalf("second claim = %+v, want held/holder-a", second)
	}
	reclaimed := claim("holder-c", "--reclaim")
	if reclaimed["claimed"] != true || reclaimed["reason"] != "reclaim" {
		t.Fatalf("reclaim = %+v, want claimed/reclaim", reclaimed)
	}

	// The live claim must be visible to the next planning pass.
	stdout, _, code := captureOutput(func() int {
		return runStatusCmd(ctx, []string{"--db", dbPath, "--per-type", "--scan-id", scanID})
	})
	if code != 0 {
		t.Fatalf("--per-type failed: %s", stdout)
	}
	var perType []struct {
		VulnType       string `json:"vuln_type"`
		InFlightRanges []struct {
			Range  string `json:"range"`
			Holder string `json:"holder"`
		} `json:"in_flight_ranges"`
	}
	if err := json.Unmarshal([]byte(stdout), &perType); err != nil {
		t.Fatalf("--per-type output is not JSON: %s", stdout)
	}
	var found bool
	for _, pt := range perType {
		if pt.VulnType != "null-deref" {
			if len(pt.InFlightRanges) != 0 {
				t.Errorf("unexpected in_flight_ranges on %s: %+v", pt.VulnType, pt.InFlightRanges)
			}
			continue
		}
		found = true
		if len(pt.InFlightRanges) != 1 || pt.InFlightRanges[0].Range != "1-20" || pt.InFlightRanges[0].Holder != "holder-c" {
			t.Fatalf("in_flight_ranges not exposed: %+v", pt.InFlightRanges)
		}
	}
	if !found {
		t.Fatal("null-deref missing from --per-type output")
	}

	// An unknown type is rejected instead of reserving an unusable batch.
	stdout, _, code = captureOutput(func() int {
		return runStatusCmd(ctx, []string{"--db", dbPath, "--scan-id", scanID, "--claim-type", "not-a-type", "--claim-range", "1-20", "--claim-holder", "x"})
	})
	if code == 0 {
		t.Fatalf("unknown claim type must fail, got: %s", stdout)
	}
}

func TestEnrichPerTypeStatusBudgetViolations(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: "sc_test", VulnType: "null-deref", SeedCount: 264, FinalCount: 264}); err != nil {
		t.Fatal(err)
	}
	// A batch that blew every budget.
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_test", VulnType: "null-deref", RangeStr: "121-160", SubagentID: "p4",
		Written: 0, Dismissed: 40, EvidenceOpens: 25, SourceReads: 6, RepoGreps: 2,
	}); err != nil {
		t.Fatal(err)
	}
	// A batch that stayed within budget must not surface.
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_test", VulnType: "null-deref", RangeStr: "1-40", SubagentID: "p1",
		Written: 0, Dismissed: 40, EvidenceOpens: 11, SourceReads: 3, RepoGreps: 0,
	}); err != nil {
		t.Fatal(err)
	}

	statuses, err := store.ListPerTypeStatus(ctx, "sc_test", func(string) []string { return []string{"CWE-476"} })
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := enrichPerTypeStatus(ctx, store, "sc_test", statuses)
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched, got %d", len(enriched))
	}
	v := enriched[0].BudgetViolations
	if len(v) != 1 {
		t.Fatalf("budget_violations = %+v, want exactly 1 (range 121-160)", v)
	}
	if v[0].Range != "121-160" || v[0].EvidenceOpens != 25 {
		t.Errorf("violation record mismatch: %+v", v[0])
	}
	if len(v[0].Over) != 3 {
		t.Errorf("over = %v, want all three budgets [source_reads evidence_opens repo_greps]", v[0].Over)
	}
}

func TestPersistSettlementReports(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	project := t.TempDir()
	dbPath := project + "/.codeagent/secguard-clang/.sgre/sgre.db"
	tmp := project + "/.codeagent/secguard-clang/.sgre/.tmp"
	writeReport(t, tmp, "sub-a-report.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-69","cwe":"CWE-476","written":3,"dismissed":66,"source_reads":1,"evidence_opens":43,"repo_greps":0}]
	}`)
	writeReport(t, tmp, "sub-partial-report.json", `{"format_version":1,"subagent_id":"sub-p","scan_id":"sc_test"`)

	res := listSubagentReports(dbPath, "sc_test")
	if err := persistSettlementReports(ctx, store, res); err != nil {
		t.Fatal(err)
	}

	rows, err := store.ListSettlementStatsByScan(ctx, "sc_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 persisted row (partial excluded), got %d", len(rows))
	}
	if rows[0].VulnType != "null-deref" || rows[0].RangeStr != "1-69" || rows[0].EvidenceOpens != 43 || rows[0].Dismissed != 66 {
		t.Errorf("persisted row mismatch: %+v", rows[0])
	}

	// Re-persisting the same file must stay idempotent.
	if err := persistSettlementReports(ctx, store, listSubagentReports(dbPath, "sc_test")); err != nil {
		t.Fatal(err)
	}
	rows, _ = store.ListSettlementStatsByScan(ctx, "sc_test")
	if len(rows) != 1 {
		t.Fatalf("re-persist must not duplicate, got %d", len(rows))
	}
}

// TestPersistSettlementReportsNewestWins pins the last-write-wins direction:
// two workers settling the same (type, range) under different subagent ids must
// end with the NEWEST report's accounting, not the older snapshot that happens
// to be applied last.
func TestPersistSettlementReportsNewestWins(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	project := t.TempDir()
	dbPath := project + "/.codeagent/secguard-clang/.sgre/sgre.db"
	tmp := project + "/.codeagent/secguard-clang/.sgre/.tmp"
	writeReport(t, tmp, "sub-old-report.json", `{
	  "format_version": 1, "subagent_id": "sub-old", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":1,"dismissed":99,"evidence_opens":2}]
	}`)
	writeReport(t, tmp, "sub-new-report.json", `{
	  "format_version": 1, "subagent_id": "sub-new", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":8,"dismissed":92,"evidence_opens":9}]
	}`)
	oldPath := filepath.Join(tmp, "sub-old-report.json")
	newPath := filepath.Join(tmp, "sub-new-report.json")
	if err := os.Chtimes(oldPath, time.Now().Add(-2*time.Minute), time.Now().Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newPath, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	if err := persistSettlementReports(ctx, store, listSubagentReports(dbPath, "sc_test")); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListSettlementStatsByScan(ctx, "sc_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row for the shared type+range, got %d", len(rows))
	}
	if rows[0].SubagentID != "sub-new" || rows[0].Written != 8 || rows[0].Dismissed != 92 || rows[0].EvidenceOpens != 9 {
		t.Errorf("newest settlement must win: %+v", rows[0])
	}
}

func TestEnrichPerTypeStatusRemainingWhenDone(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: "sc_test", VulnType: "uninit", SeedCount: 90, FinalCount: 90}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAIStageDone(ctx, "sc_test", "uninit"); err != nil {
		t.Fatal(err)
	}

	statuses, err := store.ListPerTypeStatus(ctx, "sc_test", func(string) []string { return []string{"CWE-457"} })
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := enrichPerTypeStatus(ctx, store, "sc_test", statuses)
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched, got %d", len(enriched))
	}
	e := enriched[0]
	if e.TerminalState != "done" {
		t.Fatalf("terminal_state = %q, want done", e.TerminalState)
	}
	// All 90 candidates were dismissed (not persisted to candidate_verdicts), so
	// remaining must read 0, never the candidate_count residue.
	if e.Remaining != 0 {
		t.Errorf("remaining = %d, want 0 (done type has no unclassified candidates)", e.Remaining)
	}
}

func TestSettlementWallMS(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	scanStart := time.Now().Add(-10 * time.Minute).Unix()
	if err := store.UpsertScanRun(ctx, &db.ScanRun{ScanID: "sc_test", CreatedAt: scanStart}); err != nil {
		t.Fatal(err)
	}
	rep := subagentReport{ScanID: "sc_test", ModTime: time.Now().Format(time.RFC3339)}
	wall := settlementWallMS(ctx, store, rep)
	if wall < 500000 || wall > 700000 {
		t.Errorf("wall_ms = %d, want ~600000", wall)
	}
	if got := settlementWallMS(ctx, db.NewTestStore(t), rep); got != 0 {
		t.Errorf("no scan_run must yield 0, got %d", got)
	}
	if got := settlementWallMS(ctx, store, subagentReport{ScanID: "sc_test"}); got != 0 {
		t.Errorf("no mtime must yield 0, got %d", got)
	}
}

func TestSettlementQueueWorkMS(t *testing.T) {
	rep := subagentReport{
		DispatchedAt: "2026-11-03T10:00:00Z",
		StartedAt:    "2026-11-03T10:00:03Z",
		ModTime:      "2026-11-03T10:00:08Z",
	}
	q, w := settlementQueueWorkMS(rep)
	if q != 3000 || w != 5000 {
		t.Errorf("queue/work = %d/%d, want 3000/5000", q, w)
	}

	if q, w := settlementQueueWorkMS(subagentReport{ModTime: "2026-11-03T10:00:08Z"}); q != 0 || w != 0 {
		t.Errorf("missing timestamps must yield 0/0, got %d/%d", q, w)
	}
	if q, w := settlementQueueWorkMS(subagentReport{DispatchedAt: "nope", StartedAt: "also-nope"}); q != 0 || w != 0 {
		t.Errorf("malformed timestamps must yield 0/0, got %d/%d", q, w)
	}
	// Negative queue (clock skew) must clamp to 0 while work stays positive.
	q2, w2 := settlementQueueWorkMS(subagentReport{
		DispatchedAt: "2026-11-03T10:00:05Z", StartedAt: "2026-11-03T10:00:03Z", ModTime: "2026-11-03T10:00:08Z",
	})
	if q2 != 0 || w2 != 5000 {
		t.Errorf("negative queue must clamp to 0: queue=%d work=%d, want 0/5000", q2, w2)
	}
}
