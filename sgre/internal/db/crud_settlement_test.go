//go:build !nosqlite

package db

import (
	"context"
	"testing"
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
