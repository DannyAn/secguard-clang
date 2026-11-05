//go:build !nosqlite

package db

import (
	"context"
	"testing"
	"time"
)

func TestSettlementStatUpsertIdempotent(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	first := &SettlementStat{
		ScanID: "sc_a", VulnType: "null-deref", RangeStr: "1-10", SubagentID: "sub-1",
		Written: 2, Dismissed: 8, EvidenceOpens: 6, SourceReads: 1, RepoGreps: 0,
	}
	if err := s.UpsertSettlementStat(ctx, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := s.UpsertSettlementStat(ctx, first); err != nil {
		t.Fatalf("second upsert (idempotent): %v", err)
	}

	rows, err := s.ListSettlementStatsByScan(ctx, "sc_a")
	if err != nil {
		t.Fatalf("list by scan: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after idempotent upsert, got %d", len(rows))
	}
	if rows[0].EvidenceOpens != 6 || rows[0].Dismissed != 8 || rows[0].Written != 2 {
		t.Errorf("row mismatch: %+v", rows[0])
	}
}

func TestSettlementStatListByTypeMostRecent(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	rows := []*SettlementStat{
		{ScanID: "sc_1", VulnType: "null-deref", RangeStr: "all", SubagentID: "a", Written: 1, Dismissed: 9, EvidenceOpens: 6},
		{ScanID: "sc_2", VulnType: "null-deref", RangeStr: "all", SubagentID: "b", Written: 0, Dismissed: 10, EvidenceOpens: 6},
	}
	for i, r := range rows {
		r.CreatedAt = int64(i + 1)
		if err := s.UpsertSettlementStat(ctx, r); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	if err := s.UpsertSettlementStat(ctx, &SettlementStat{ScanID: "sc_1", VulnType: "memory-leak", RangeStr: "all", SubagentID: "c", Written: 5, Dismissed: 5, EvidenceOpens: 8, CreatedAt: 3}); err != nil {
		t.Fatalf("upsert memory-leak: %v", err)
	}

	got, err := s.ListSettlementStatsByType(ctx, "null-deref", 50)
	if err != nil {
		t.Fatalf("list by type: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 null-deref rows, got %d", len(got))
	}
	if got[0].ScanID != "sc_2" {
		t.Errorf("expected newest first, got %s", got[0].ScanID)
	}
}

func TestSettlementStatWallMSNullable(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	if err := s.UpsertSettlementStat(ctx, &SettlementStat{ScanID: "s", VulnType: "t", RangeStr: "all", SubagentID: "x"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListSettlementStatsByScan(ctx, "s")
	if len(rows) != 1 || rows[0].WallMS != 0 {
		t.Fatalf("wall_ms should read 0 when unset: %+v", rows)
	}

	if err := s.UpsertSettlementStat(ctx, &SettlementStat{ScanID: "s", VulnType: "t", RangeStr: "all", SubagentID: "x", WallMS: 5000}); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSettlementStatsByScan(ctx, "s")
	if len(rows) != 1 || rows[0].WallMS != 5000 {
		t.Fatalf("wall_ms should persist: %+v", rows)
	}
}

// TestSettlementStatLastWriteWins pins the one-row-per-(scan_id, vuln_type,
// range_str) invariant (Issue #207 B.5): a duplicate dispatch of the same range
// by two subagents previously wrote two rows with conflicting counts; now the
// newer settlement overwrites.
func TestSettlementStatLastWriteWins(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	first := &SettlementStat{ScanID: "sc_d", VulnType: "null-deref", RangeStr: "1-100", SubagentID: "sub-1", Written: 3, Dismissed: 97, CreatedAt: 1}
	if err := s.UpsertSettlementStat(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := &SettlementStat{ScanID: "sc_d", VulnType: "null-deref", RangeStr: "1-100", SubagentID: "sub-2", Written: 8, Dismissed: 92, CreatedAt: 2}
	if err := s.UpsertSettlementStat(ctx, second); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ListSettlementStatsByScan(ctx, "sc_d")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after same-range duplicate dispatch, got %d", len(rows))
	}
	if rows[0].SubagentID != "sub-2" || rows[0].Written != 8 || rows[0].Dismissed != 92 {
		t.Errorf("later write must overwrite: %+v", rows[0])
	}
}

// TestSettlementStatQueueWorkMS pins the queue_ms/work_ms persistence split from
// wall_ms (Issue #207 B.5).
func TestSettlementStatQueueWorkMS(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "s", VulnType: "t", RangeStr: "all", SubagentID: "x",
		WallMS: 9000, QueueMS: 3000, WorkMS: 6000,
	}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListSettlementStatsByScan(ctx, "s")
	if len(rows) != 1 || rows[0].QueueMS != 3000 || rows[0].WorkMS != 6000 {
		t.Fatalf("queue_ms/work_ms must persist: %+v", rows[0])
	}
}

func TestSettlementTaskStatusLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	// Dispatch a batch: status=dispatched, retry_count=0.
	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "sc_x", VulnType: "null-deref", RangeStr: "1-100", SubagentID: "w1", Status: "dispatched",
	}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListSettlementStatsByScan(ctx, "sc_x")
	if len(rows) != 1 || rows[0].Status != "dispatched" || rows[0].RetryCount != 0 {
		t.Fatalf("dispatched row wrong: %+v", rows)
	}

	// A settlement-file write (no explicit status) defaults to done.
	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "sc_y", VulnType: "uninit", RangeStr: "all", SubagentID: "w2",
	}); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSettlementStatsByScan(ctx, "sc_y")
	if rows[0].Status != "done" {
		t.Fatalf("default status must be done: %+v", rows[0])
	}

	// Mark the dispatched batch done.
	if err := s.MarkSettlementStatus(ctx, "sc_x", "null-deref", "1-100", "w1", "done"); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSettlementStatsByScan(ctx, "sc_x")
	if rows[0].Status != "done" {
		t.Fatalf("status not updated: %+v", rows[0])
	}

	// Retry bump re-marks dispatched and increments the counter.
	if err := s.IncrementSettlementRetry(ctx, "sc_x", "null-deref", "1-100", "w1"); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListSettlementStatsByScan(ctx, "sc_x")
	if rows[0].Status != "dispatched" || rows[0].RetryCount != 1 {
		t.Fatalf("retry not applied: %+v", rows[0])
	}
}

// TestSettlementClaim_AtomicPlaceholder pins the pre-dispatch reservation
// (#217): the first claim wins, a second concurrent claim on the same
// type+range loses with the holder surfaced, and a stale claim is taken over.
func TestSettlementClaim_AtomicPlaceholder(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)
	nowSec := time.Now().Unix()

	first, err := s.ClaimSettlementRange(ctx, "sc_c", "buffer-overflow", "1-20", "holder-a", nowSec-60, false)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Claimed || first.Reason != "new" {
		t.Fatalf("first claim = %+v, want claimed/new", first)
	}
	row, err := s.GetSettlementStat(ctx, "sc_c", "buffer-overflow", "1-20")
	if err != nil || row == nil {
		t.Fatalf("claim row missing: %v", err)
	}
	if row.Status != "dispatched" || row.SubagentID != "holder-a" {
		t.Errorf("claim row = %+v, want dispatched/holder-a", row)
	}

	second, err := s.ClaimSettlementRange(ctx, "sc_c", "buffer-overflow", "1-20", "holder-b", nowSec-60, false)
	if err != nil {
		t.Fatal(err)
	}
	if second.Claimed {
		t.Fatalf("a fresh claim must not be stolen: %+v", second)
	}
	if second.Reason != "held" || second.Holder != "holder-a" {
		t.Errorf("held claim = %+v, want held/holder-a", second)
	}

	// staleBefore in the future makes the stored claim stale: takeover + retry.
	stale, err := s.ClaimSettlementRange(ctx, "sc_c", "buffer-overflow", "1-20", "holder-c", nowSec+3600, false)
	if err != nil {
		t.Fatal(err)
	}
	if !stale.Claimed || stale.Reason != "stale" {
		t.Fatalf("stale claim = %+v, want claimed/stale", stale)
	}
	if stale.RetryCount != 1 {
		t.Errorf("retry_count = %d, want 1", stale.RetryCount)
	}
	row, _ = s.GetSettlementStat(ctx, "sc_c", "buffer-overflow", "1-20")
	if row.SubagentID != "holder-c" || row.RetryCount != 1 {
		t.Errorf("takeover row = %+v", row)
	}
}

func TestSettlementClaim_DoneHeldUnlessReclaim(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "sc_d", VulnType: "uninit", RangeStr: "1-50", SubagentID: "w1",
		Written: 1, Dismissed: 49,
	}); err != nil {
		t.Fatal(err)
	}
	held, err := s.ClaimSettlementRange(ctx, "sc_d", "uninit", "1-50", "holder", time.Now().Unix(), false)
	if err != nil {
		t.Fatal(err)
	}
	if held.Claimed || held.Reason != "done" {
		t.Fatalf("done range claim = %+v, want held/done", held)
	}

	reclaimed, err := s.ClaimSettlementRange(ctx, "sc_d", "uninit", "1-50", "holder", time.Now().Unix(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !reclaimed.Claimed || reclaimed.Reason != "reclaim" {
		t.Fatalf("reclaim = %+v, want claimed/reclaim", reclaimed)
	}
}

func TestSettlementClaim_FailedRowRetried(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	if err := s.UpsertSettlementStat(ctx, &SettlementStat{
		ScanID: "sc_f", VulnType: "uninit", RangeStr: "1-50", SubagentID: "w1", Status: "failed",
	}); err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimSettlementRange(ctx, "sc_f", "uninit", "1-50", "w2", time.Now().Unix(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !claim.Claimed || claim.Reason != "retry" {
		t.Fatalf("failed row claim = %+v, want claimed/retry", claim)
	}
}
