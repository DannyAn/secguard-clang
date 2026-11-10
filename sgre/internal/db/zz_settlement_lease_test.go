//go:build !nosqlite

package db

import (
	"context"
	"testing"
	"time"
)

// Overlap fencing: ranges are candidate intervals, not opaque labels — a live
// or settled "1-100" blocks "1-40" (and "all"), so two orchestrators can never
// run the same candidates under different range spellings.
func TestClaimOverlapRejected(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: "sc_o", VulnType: "null-deref", SeedCount: 120, FinalCount: 100}); err != nil {
		t.Fatal(err)
	}
	nowMS := time.Now().UnixMilli()
	first, err := s.ClaimSettlementRange(ctx, "sc_o", "null-deref", "1-100", "holder-a", nowMS, false)
	if err != nil || !first.Claimed {
		t.Fatalf("first claim = %+v err=%v", first, err)
	}

	overlap, err := s.ClaimSettlementRange(ctx, "sc_o", "null-deref", "1-40", "holder-b", nowMS, false)
	if err != nil {
		t.Fatal(err)
	}
	if overlap.Claimed || overlap.Reason != "overlap" {
		t.Fatalf("1-40 inside a live 1-100 must lose with overlap, got %+v", overlap)
	}
	all, err := s.ClaimSettlementRange(ctx, "sc_o", "null-deref", "all", "holder-b", nowMS, false)
	if err != nil {
		t.Fatal(err)
	}
	if all.Claimed {
		t.Fatalf("'all' overlaps every live range and must lose: %+v", all)
	}
	disjoint, err := s.ClaimSettlementRange(ctx, "sc_o", "null-deref", "1-100", "holder-b", nowMS, false)
	if err != nil {
		t.Fatal(err)
	}
	if disjoint.Claimed || disjoint.Reason != "held" {
		t.Fatalf("the exact same live range reports held (not overlap): %+v", disjoint)
	}

	// A done range also blocks an overlapping claim with overlap-done.
	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "sc_o", VulnType: "null-deref", RangeStr: "1-100", SubagentID: "holder-a", Status: "done",
	}); err != nil {
		t.Fatal(err)
	}
	again, err := s.ClaimSettlementRange(ctx, "sc_o", "null-deref", "50-60", "holder-b", nowMS, false)
	if err != nil {
		t.Fatal(err)
	}
	if again.Claimed || again.Reason != "overlap-done" {
		t.Fatalf("50-60 inside a done 1-100 must lose with overlap-done, got %+v", again)
	}
}

// A claim on a nonexistent scan or type is rejected instead of minting orphans.
func TestClaimRejectsUnknownScanAndType(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: "sc_k", VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSettlementRange(ctx, "sc_missing", "null-deref", "all", "h", time.Now().UnixMilli(), false); err == nil {
		t.Fatal("claim on an unknown scan_id must fail")
	}
	if _, err := s.ClaimSettlementRange(ctx, "sc_k", "buffer-overflow", "all", "h", time.Now().UnixMilli(), false); err == nil {
		t.Fatal("claim on a type with no scan_stats must fail")
	}
}

// A live holder whose heartbeat keeps being renewed is NOT reclaimed at the
// claim TTL; a dead one (no heartbeat) is.
func TestLeaseRenewalPreventsStaleReclaim(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: "sc_l", VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	nowMS := time.Now().UnixMilli()
	// A claim created an hour ago whose heartbeat was renewed just now:
	// created_at alone would look stale, the fresh heartbeat must win.
	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "sc_l", VulnType: "null-deref", RangeStr: "all", SubagentID: "alive",
		Status: "dispatched", CreatedAt: nowMS - 3_600_000, HeartbeatAt: nowMS,
	}); err != nil {
		t.Fatal(err)
	}
	row, err := s.GetSettlementStat(ctx, "sc_l", "null-deref", "all")
	if err != nil || row == nil {
		t.Fatalf("claim row: %v", err)
	}
	if row.HeartbeatAt != nowMS {
		t.Fatalf("heartbeat_at = %d, want %d", row.HeartbeatAt, nowMS)
	}
	staleBefore := nowMS - 1_800_000
	claim, err := s.ClaimSettlementRange(ctx, "sc_l", "null-deref", "all", "thief", staleBefore, false)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Claimed {
		t.Fatalf("a fresh-heartbeat holder must not be reclaimed: %+v", claim)
	}

	// The dead holder (no heartbeat, created an hour ago) IS reclaimed — on a
	// separate type so the alive holder's "all" range does not overlap it.
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: "sc_l", VulnType: "buffer-overflow", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "sc_l", VulnType: "buffer-overflow", RangeStr: "1-2", SubagentID: "dead",
		Status: "dispatched", CreatedAt: nowMS - 3_600_000,
	}); err != nil {
		t.Fatal(err)
	}
	claim, err = s.ClaimSettlementRange(ctx, "sc_l", "buffer-overflow", "1-2", "thief", staleBefore, false)
	if err != nil {
		t.Fatal(err)
	}
	if !claim.Claimed || claim.Reason != "stale" {
		t.Fatalf("a dead holder (no heartbeat) must be reclaimed as stale: %+v", claim)
	}
}

// Release/fail-claim is a CAS on the current holder: another holder cannot
// close the batch, and a released range becomes claimable again.
func TestReleaseSettlementClaimCAS(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: "sc_r", VulnType: "null-deref", SeedCount: 10, FinalCount: 5}); err != nil {
		t.Fatal(err)
	}
	nowMS := time.Now().UnixMilli()
	if _, err := s.ClaimSettlementRange(ctx, "sc_r", "null-deref", "all", "holder-a", nowMS, false); err != nil {
		t.Fatal(err)
	}

	ok, err := s.ReleaseSettlementClaim(ctx, "sc_r", "null-deref", "all", "holder-b", "released")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("another holder's release must be a no-op")
	}
	row, _ := s.GetSettlementStat(ctx, "sc_r", "null-deref", "all")
	if row.Status != "dispatched" {
		t.Fatalf("status = %q, want dispatched after a foreign release", row.Status)
	}

	ok, err = s.ReleaseSettlementClaim(ctx, "sc_r", "null-deref", "all", "holder-a", "released")
	if err != nil || !ok {
		t.Fatalf("the holder's own release must succeed: ok=%v err=%v", ok, err)
	}
	row, _ = s.GetSettlementStat(ctx, "sc_r", "null-deref", "all")
	if row.Status != "released" {
		t.Fatalf("status = %q, want released", row.Status)
	}

	claim, err := s.ClaimSettlementRange(ctx, "sc_r", "null-deref", "all", "holder-c", nowMS, false)
	if err != nil || !claim.Claimed {
		t.Fatalf("a released range must be claimable again: %+v err=%v", claim, err)
	}
}

// The verdict identity matches the findings identity: two variables on one
// line are two verdicts, and a retry that omits function updates in place.
func TestCandidateVerdictIdentityTwoVariables(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)
	for _, v := range []*CandidateVerdict{
		{ScanID: "sc_v", VulnType: "null-deref", RuleID: "CWE-476", FilePath: "a.c", LineNumber: 10, FunctionName: "f", Variable: "p", Verdict: "dismissed", Reason: "guarded"},
		{ScanID: "sc_v", VulnType: "null-deref", RuleID: "CWE-476", FilePath: "a.c", LineNumber: 10, FunctionName: "f", Variable: "q", Verdict: "dismissed", Reason: "guarded"},
	} {
		if _, err := s.UpsertCandidateVerdict(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	// Retry the first variable WITHOUT function: must update, not duplicate.
	if _, err := s.UpsertCandidateVerdict(ctx, &CandidateVerdict{
		ScanID: "sc_v", VulnType: "null-deref", RuleID: "CWE-476", FilePath: "a.c", LineNumber: 10, Variable: "p", Verdict: "dismissed", Reason: "guarded (retry)",
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListCandidateVerdicts(ctx, "sc_v")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected exactly 2 verdict rows (one per variable), got %d", len(rows))
	}
	counts, err := s.CountCandidateVerdictsByType(ctx, "sc_v")
	if err != nil {
		t.Fatal(err)
	}
	if counts["null-deref"] != 2 {
		t.Errorf("dismissed_count = %d, want 2", counts["null-deref"])
	}
}
