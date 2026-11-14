//go:build !nosqlite

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// TestMeasureAIStageTiming derives the AI stage from settlement timestamps:
// each settled row carries its finish time and its own queue/work split, so the
// total spans the earliest reconstructed dispatch to the latest finish.
func TestMeasureAIStageTiming(t *testing.T) {
	base := int64(1_700_000_000_000)
	rows := []*db.SettlementStat{
		{VulnType: "null-deref", Status: "done", FinishedAt: base, QueueMS: 60_000, WorkMS: 240_000},
		{VulnType: "buffer-overflow", Status: "done", FinishedAt: base + 600_000, QueueMS: 60_000, WorkMS: 120_000},
		// A claim that never settled must not count.
		{VulnType: "uninit", Status: "dispatched", CreatedAt: base / 1000},
	}
	timing := measureAIStageTiming(rows)
	if timing.TotalMS != 900_000 {
		t.Fatalf("total = %d, want 900000 (earliest dispatch -> latest finish)", timing.TotalMS)
	}
	if timing.Batches != 2 {
		t.Errorf("batches = %d, want 2 (the dispatched claim does not count)", timing.Batches)
	}
	if got := timing.PerTypeMS["null-deref"]; got != 300_000 {
		t.Errorf("null-deref span = %d, want 300000", got)
	}
	if got := timing.PerTypeMS["buffer-overflow"]; got != 180_000 {
		t.Errorf("buffer-overflow span = %d, want 180000", got)
	}
	if timing.Source != "self-measured" {
		t.Errorf("source = %q, want self-measured", timing.Source)
	}
}

// TestReportAuditSelfMeasuresAIDuration proves the audit records the measured AI
// stage without --ai-duration-ms, and still honours the flag as an override.
func TestReportAuditSelfMeasuresAIDuration(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(d)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertScanRun(ctx, &db.ScanRun{ScanID: scanID}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UnixMilli() - 3_600_000
	for _, st := range []*db.SettlementStat{
		{ScanID: scanID, VulnType: "null-deref", RangeStr: "all", SubagentID: "a", Written: 2, Dismissed: 3, FinishedAt: base, QueueMS: 60_000, WorkMS: 240_000},
		{ScanID: scanID, VulnType: "buffer-overflow", RangeStr: "all", SubagentID: "b", Written: 1, Dismissed: 4, FinishedAt: base + 600_000, QueueMS: 60_000, WorkMS: 120_000},
	} {
		if err := store.UpsertSettlementStat(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MarkAIStageDone(ctx, scanID, "null-deref"); err != nil {
		t.Fatal(err)
	}
	store.Close()

	stdout, _, code := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", scanID})
	})
	if code != 0 {
		t.Fatalf("audit failed: %s", stdout)
	}
	var out struct {
		AIStage aiStageTiming `json:"ai_stage"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("audit output is not JSON: %s", stdout)
	}
	if out.AIStage.TotalMS != 900_000 || out.AIStage.Source != "self-measured" {
		t.Fatalf("ai_stage = %+v, want self-measured 900000", out.AIStage)
	}
	if got := out.AIStage.PerTypeMS["buffer-overflow"]; got != 180_000 {
		t.Errorf("per-type buffer-overflow = %d, want 180000", got)
	}

	d2, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store2 := db.NewStore(d2)
	run, err := store2.GetScanRun(ctx, scanID)
	if err != nil || run == nil {
		t.Fatalf("get scan run: %v", err)
	}
	if run.AIDurationMs != 900_000 || run.AIDurationSource != "self-measured" {
		t.Errorf("persisted ai duration = %d/%q, want 900000/self-measured", run.AIDurationMs, run.AIDurationSource)
	}
	store2.Close()

	// The explicit flag still wins: it is the override path.
	stdout, _, code = captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", scanID, "--ai-duration-ms", "1234"})
	})
	if code != 0 {
		t.Fatalf("override audit failed: %s", stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.AIStage.TotalMS != 1234 || out.AIStage.Source != "override" {
		t.Fatalf("override ai_stage = %+v, want 1234/override", out.AIStage)
	}
}

// TestAuditAbsorbsSettlementFileWithoutStatusReports pins the fix for the
// concurrency-scheduling gap this session exposed: the happy path is
// `report --complete-type` + `report --audit`, and it does not call
// `status --reports`. The audit itself must therefore absorb the .sgre/.tmp
// settlement reports — otherwise it self-measures ai_duration=0 and the type's
// pre-dispatch claim keeps reading as in-flight for the rest of claim_ttl.
func TestAuditAbsorbsSettlementFileWithoutStatusReports(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(d)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertScanRun(ctx, &db.ScanRun{ScanID: scanID}); err != nil {
		t.Fatal(err)
	}
	// A pre-dispatch claim that the orchestrator never closed (the bug).
	if _, err := store.ClaimSettlementRange(ctx, scanID, "null-deref", "all", "holder-x", 0, false); err != nil {
		t.Fatal(err)
	}
	// Every candidate carries a terminal verdict (2 confirmed + 3 dismissed),
	// so the ledger-derived completion lets the audit through.
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
	store.Close()

	m := time.Now().Add(-time.Minute)
	body := `{
  "format_version": 1,
  "subagent_id": "worker-x",
  "scan_id": "` + scanID + `",
  "dispatched_at": "` + m.Add(-5*time.Minute).Format(time.RFC3339Nano) + `",
  "started_at": "` + m.Add(-4*time.Minute).Format(time.RFC3339Nano) + `",
  "processed_types": [
    {"type": "null-deref", "range": "all", "cwe": "CWE-476", "written": 2, "dismissed": 3, "source_reads": 0, "evidence_opens": 1, "repo_greps": 0}
  ]
}`
	writeSettlementReport(t, root, "worker-x-report.json", body, m)

	stdout, _, code := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--audit", "--scan-id", scanID})
	})
	if code != 0 {
		t.Fatalf("audit failed: %s", stdout)
	}
	var out struct {
		AIStage aiStageTiming `json:"ai_stage"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("audit output is not JSON: %s", stdout)
	}
	if out.AIStage.TotalMS <= 0 || out.AIStage.Source != "self-measured" {
		t.Fatalf("audit did not self-measure: %+v (it must absorb .tmp reports itself)", out.AIStage)
	}

	d2, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store2 := db.NewStore(d2)
	defer store2.Close()
	st, err := store2.GetSettlementStat(ctx, scanID, "null-deref", "all")
	if err != nil || st == nil {
		t.Fatalf("settlement row: %v", err)
	}
	if st.Status != "done" {
		t.Errorf("claim status = %q, want done (audit must close the pre-dispatch claim)", st.Status)
	}
	if st.Written != 2 || st.Dismissed != 3 {
		t.Errorf("accounting = %d/%d, want 2/3 (absorbed from the .tmp report)", st.Written, st.Dismissed)
	}
}

// TestCompleteTypeSettlesDispatchedClaim pins the VERDICT-LEDGER completion
// rule: --complete-type refuses while any candidate lacks a terminal verdict
// (unclassified > 0), and once every candidate carries one it succeeds AND
// settles the type's own dispatched claims — even when the subagent never
// wrote a settlement file (the F13 claim ↔ complete-type deadlock).
func TestCompleteTypeSettlesDispatchedClaim(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(d)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimSettlementRange(ctx, scanID, "null-deref", "all", "holder-x", 0, false)
	if err != nil || claim == nil || !claim.Claimed {
		t.Fatalf("claim: %+v err=%v", claim, err)
	}

	// A live claim with zero settled candidates: complete-type must refuse
	// (unclassified = 5 > 0) and must NOT flip the claim to done.
	stdout, _, code := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--complete-type", "null-deref", "--scan-id", scanID})
	})
	if code == 0 {
		t.Fatalf("complete-type must refuse a live, uncovered claim: %s", stdout)
	}
	var refusal struct {
		Status       string `json:"status"`
		Unclassified int    `json:"unclassified"`
	}
	if err := json.Unmarshal([]byte(stdout), &refusal); err != nil {
		t.Fatalf("refusal output is not JSON: %s", stdout)
	}
	if refusal.Status != "incomplete" || refusal.Unclassified != 5 {
		t.Errorf("refusal = %+v, want incomplete with unclassified 5", refusal)
	}

	// Every candidate now carries a terminal verdict (2 confirmed + 3
	// dismissed) — complete-type succeeds and settles the claim even though
	// no settlement file was ever written.
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
	store.Close()

	stdout, _, code = captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--complete-type", "null-deref", "--scan-id", scanID})
	})
	if code != 0 {
		t.Fatalf("complete-type failed after full verdict coverage: %s", stdout)
	}

	d2, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store2 := db.NewStore(d2)
	defer store2.Close()
	st, err := store2.GetSettlementStat(ctx, scanID, "null-deref", "all")
	if err != nil || st == nil {
		t.Fatalf("settlement row: %v", err)
	}
	if st.Status != "done" {
		t.Errorf("claim status after complete-type = %q, want done", st.Status)
	}
	stats, err := store2.ListScanStats(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stats {
		if s.VulnType == "null-deref" && s.AIStageStatus != "done" {
			t.Errorf("ai_stage_status = %q, want done", s.AIStageStatus)
		}
	}
}

// TestStatusShowLimits proves the concurrency caps are queryable without a DB,
// and that a deployment can override the documented host cap.
func TestStatusShowLimits(t *testing.T) {
	t.Setenv("SECGUARD_AI_HOST_MAX_CONCURRENCY", "")
	stdout, _, code := captureOutput(func() int {
		return runStatusCmd(context.Background(), []string{"--show-limits"})
	})
	if code != 0 {
		t.Fatalf("--show-limits failed: %s", stdout)
	}
	var out struct {
		AIStage struct {
			HostMaxConcurrency int `json:"host_max_concurrency"`
			ClaimTTLMS         int `json:"claim_ttl_ms"`
		} `json:"ai_stage"`
		Pipeline struct {
			PlanConcurrency int `json:"plan_concurrency"`
		} `json:"pipeline"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("--show-limits output is not JSON: %s", stdout)
	}
	if out.AIStage.HostMaxConcurrency != aiHostMaxConcurrencyDefault {
		t.Errorf("host_max_concurrency = %d, want %d", out.AIStage.HostMaxConcurrency, aiHostMaxConcurrencyDefault)
	}
	if out.AIStage.ClaimTTLMS != int(settlementClaimTTL/time.Millisecond) {
		t.Errorf("claim_ttl_ms = %d, want %d", out.AIStage.ClaimTTLMS, settlementClaimTTL/time.Millisecond)
	}
	if out.Pipeline.PlanConcurrency <= 0 {
		t.Errorf("plan_concurrency = %d, want > 0", out.Pipeline.PlanConcurrency)
	}

	t.Setenv("SECGUARD_AI_HOST_MAX_CONCURRENCY", "4")
	stdout, _, code = captureOutput(func() int {
		return runStatusCmd(context.Background(), []string{"--show-limits"})
	})
	if code != 0 {
		t.Fatalf("--show-limits override failed: %s", stdout)
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.AIStage.HostMaxConcurrency != 4 {
		t.Errorf("override host_max_concurrency = %d, want 4", out.AIStage.HostMaxConcurrency)
	}
}

// writeSettlementReport drops one settlement JSON into <dbDir>/.tmp.
func writeSettlementReport(t *testing.T, dbDir, name, body string, mtime time.Time) {
	t.Helper()
	dir := filepath.Join(dbDir, ".tmp")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

const settlementReportBody = `{
  "format_version": 1,
  "subagent_id": "sub-a",
  "scan_id": "sc_2026-01-01_000000_abcdef",
  "processed_types": [
    {"type": "null-deref", "range": "1-10", "cwe": "CWE-476", "written": 2, "dismissed": 3, "source_reads": 0, "evidence_opens": 0, "repo_greps": 0}
  ]
}`

// TestStatusReportsHeartbeatProgress exposes a machine liveness/progress signal:
// the settled report's mtime age, a stalled flag, and classified/total.
func TestStatusReportsHeartbeatProgress(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(d)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 10, FinalCount: 10}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	writeSettlementReport(t, root, "sub-a-chunk-3.json", settlementReportBody, time.Now().Add(-20*time.Minute))

	stdout, _, code := captureOutput(func() int {
		return runStatusCmd(ctx, []string{"--db", dbPath, "--reports", "--scan-id", scanID})
	})
	if code != 0 {
		t.Fatalf("--reports failed: %s", stdout)
	}
	var res struct {
		Reports []struct {
			HeartbeatAgeMS int64 `json:"heartbeat_age_ms"`
			Stalled        bool  `json:"stalled"`
			Progress       *struct {
				Classified int     `json:"classified"`
				Total      int     `json:"total"`
				Percent    float64 `json:"percent"`
			} `json:"progress"`
		} `json:"reports"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("--reports output is not JSON: %s", stdout)
	}
	if len(res.Reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(res.Reports))
	}
	rep := res.Reports[0]
	if rep.HeartbeatAgeMS < int64(settlementHeartbeatStall/time.Millisecond) {
		t.Errorf("heartbeat_age_ms = %d, want >= %d", rep.HeartbeatAgeMS, settlementHeartbeatStall/time.Millisecond)
	}
	if !rep.Stalled {
		t.Error("an unfinished snapshot older than the stall window must read stalled=true")
	}
	if rep.Progress == nil || rep.Progress.Classified != 5 || rep.Progress.Total != 10 || rep.Progress.Percent != 50 {
		t.Fatalf("progress = %+v, want 5/10 (50%%)", rep.Progress)
	}
}

// TestPersistSettlementReportsMarksDoneAtomically closes the "settled but still
// pending" gap: a valid report's types are marked done in the same transaction,
// while a needs_context report deliberately leaves the type re-dispatchable.
func TestPersistSettlementReportsMarksDoneAtomically(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := db.NewTestStore(t)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "buffer-overflow", SeedCount: 10, FinalCount: 10}); err != nil {
		t.Fatal(err)
	}
	// null-deref: every candidate carries a terminal verdict (2 confirmed + 3
	// dismissed) → derived done. buffer-overflow: one candidate is needs_context
	// (NO verdict) → unclassified = 1 > 0 → stays pending.
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
	for i := 0; i < 9; i++ {
		if _, err := store.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
			ScanID: scanID, VulnType: "buffer-overflow", RuleID: "CWE-787", FilePath: "b.c",
			LineNumber: 30 + i, Variable: "buf", Verdict: "dismissed", Reason: "guarded",
		}); err != nil {
			t.Fatal(err)
		}
	}
	writeSettlementReport(t, root, "sub-a-report.json", settlementReportBody, time.Now())
	writeSettlementReport(t, root, "sub-b-report.json", `{
  "format_version": 1,
  "subagent_id": "sub-b",
  "scan_id": "sc_2026-01-01_000000_abcdef",
  "processed_types": [
    {"type": "buffer-overflow", "range": "all", "cwe": "CWE-787", "written": 0, "dismissed": 10, "source_reads": 0, "evidence_opens": 0, "repo_greps": 0}
  ],
  "needs_context": [{"candidate": 7, "reason": "needs source"}]
}`, time.Now())

	res := listSubagentReports(filepath.Join(root, "test.db"), scanID)
	if err := persistSettlementReports(ctx, store, res); err != nil {
		t.Fatalf("persist settlement reports: %v", err)
	}

	statuses, err := store.ListPerTypeStatus(ctx, scanID, planner.CWEsForType)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]string{}
	for _, st := range statuses {
		state[st.VulnType] = st.AIStageStatus
	}
	if state["null-deref"] != "done" {
		t.Errorf("null-deref ai_stage_status = %q, want done (settlement landed)", state["null-deref"])
	}
	if state["buffer-overflow"] != "pending" {
		t.Errorf("buffer-overflow ai_stage_status = %q, want pending (needs_context must stay re-dispatchable)", state["buffer-overflow"])
	}
	rows, err := store.ListSettlementStatsByScan(ctx, scanID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("settlement rows = %d, err=%v", len(rows), err)
	}
	for _, st := range rows {
		if st.FinishedAt <= 0 {
			t.Errorf("%s/%s finished_at not persisted", st.VulnType, st.RangeStr)
		}
	}
}

func TestWriteAuditReport_FilterChainTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-report.md")
	audits := []vulnAuditEntry{{
		VulnType: "null-deref", SeedCount: 100, FinalCount: 18, AIStageStatus: "done",
		Filters: `[{"name":"call_reach","input_count":100,"output_count":90},{"name":"nullable_source","input_count":90,"output_count":18}]`,
	}}
	if err := writeAuditReport(path, "test-scan", audits, reportScanOverviewStub(), aiStageTiming{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	checks := []string{
		"| Filter | Input | Output | Shrink | Removed |",
		"| call_reach | 100 | 90 | 10% | 10 |",
		"| **nullable_source** | 90 | 18 | 80% | 72 |",
		"**Top shrink:** `nullable_source` — removed 72 candidates (80% of its input).",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("audit report missing %q\n---\n%s", check, out)
		}
	}
	if strings.Contains(out, "**Filter chain:** `[") {
		t.Errorf("filter chain must not be rendered as raw JSON:\n%s", out)
	}
}

func TestWriteAuditReport_FoldsNoCandidateTypes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-report.md")
	audits := []vulnAuditEntry{
		{VulnType: "null-deref", SeedCount: 10, FinalCount: 4, AIStageStatus: "done"},
		{VulnType: "crypto-misuse", SeedCount: 0, FinalCount: 0, AIStageStatus: "pending"},
		{VulnType: "injection", SeedCount: 40, FinalCount: 0, AIStageStatus: "pending"},
	}
	if err := writeAuditReport(path, "test-scan", audits, reportScanOverviewStub(), aiStageTiming{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, check := range []string{
		"<details>",
		"Types with no converged candidates (2) — no evidence",
		"| crypto-misuse | 0 | 0 | pending | no evidence (0 raw seeds) |",
		"| injection | 40 | 0 | pending | all filtered out (40 raw seeds) |",
		"| null-deref | 10 | 4 |",
	} {
		if !strings.Contains(out, check) {
			t.Errorf("audit report missing %q\n---\n%s", check, out)
		}
	}
	if strings.Contains(out, "### crypto-misuse") {
		t.Errorf("a no-candidate type must not occupy a Filter Chain Details section:\n%s", out)
	}
}

func TestWriteAuditReport_AutoConfirmedOnlyTypeStaysInTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-report.md")
	audits := []vulnAuditEntry{
		{VulnType: "null-deref", SeedCount: 10, FinalCount: 4, AutoConfirmed: 0, AIStageStatus: "done"},
		{VulnType: "deadlock", SeedCount: 1, FinalCount: 0, AutoConfirmed: 1, AIStageStatus: "done"},
	}
	if err := writeAuditReport(path, "test-scan", audits, reportScanOverviewStub(), aiStageTiming{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	// The auto-confirmed-only type must appear in the per-skill table, not be
	// mislabelled "all filtered out" in the folded no-candidate section.
	for _, check := range []string{
		"| deadlock | 1 | 0 | 1 | 0 | done | 100% |",
	} {
		if !strings.Contains(out, check) {
			t.Errorf("audit report missing %q\n---\n%s", check, out)
		}
	}
	if strings.Contains(out, "Types with no converged candidates") {
		t.Errorf("an auto-confirmed type must not be folded as a no-candidate type:\n%s", out)
	}
}

func TestWriteAuditReport_AITimingSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-report.md")
	audits := []vulnAuditEntry{{VulnType: "null-deref", SeedCount: 10, FinalCount: 4, AIStageStatus: "done"}}
	timing := aiStageTiming{
		TotalMS:        900_000,
		PerTypeMS:      map[string]int64{"null-deref": 300_000},
		PerTypeBatches: map[string]int{"null-deref": 1},
		Batches:        2,
		Source:         "self-measured",
	}
	if err := writeAuditReport(path, "test-scan", audits, reportScanOverviewStub(), timing); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, check := range []string{
		"## AI Classification Timing",
		"Self-measured by the engine from settlement report timestamps",
		"| **TOTAL AI stage** | 2 | 15 m 0 s |",
		"| null-deref | 1 | 5 m 0 s |",
	} {
		if !strings.Contains(out, check) {
			t.Errorf("audit report missing %q\n---\n%s", check, out)
		}
	}
}

func reportScanOverviewStub() report.ScanOverview {
	return report.ScanOverview{ScanID: "test-scan", TypesScanned: 3, TypesWithCandidates: 1}
}
