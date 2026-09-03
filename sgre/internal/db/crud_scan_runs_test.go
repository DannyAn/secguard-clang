//go:build !nosqlite

package db

import (
	"context"
	"testing"
)

func TestStore_ScanRunUpsertGet(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	run := &ScanRun{
		ScanID:           "sc_2026-08-11_150000_aaaaaa",
		DurationMs:       1234,
		IndexMs:          100,
		GraphMs:          200,
		DetectorsMs:      300,
		PlanMs:           400,
		ReportMs:         50,
		FilesIndexed:     10,
		FunctionsIndexed: 20,
		SeedCount:        600,
		FinalCount:       12,
		ReportBytes:      4096,
		EvidenceBytes:    2048,
	}
	if err := s.UpsertScanRun(ctx, run); err != nil {
		t.Fatalf("UpsertScanRun: %v", err)
	}

	got, err := s.GetScanRun(ctx, run.ScanID)
	if err != nil {
		t.Fatalf("GetScanRun: %v", err)
	}
	if got == nil {
		t.Fatal("GetScanRun returned nil for an inserted row")
	}
	if got.DurationMs != 1234 || got.SeedCount != 600 || got.FinalCount != 12 || got.ReportBytes != 4096 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.EvidenceBytes != 2048 {
		t.Errorf("evidence_bytes round-trip mismatch: %+v", got)
	}
	if got.FilesIndexed != 10 || got.FunctionsIndexed != 20 {
		t.Errorf("index counts mismatch: %+v", got)
	}
}

func TestStore_ScanRunUpsertOverwrites(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	scanID := "sc_2026-08-11_150000_bbbbbb"
	if err := s.UpsertScanRun(ctx, &ScanRun{ScanID: scanID, DurationMs: 1000, FinalCount: 5}); err != nil {
		t.Fatalf("first UpsertScanRun: %v", err)
	}
	// Re-running the same scan (same scan_id) must replace the row, not add a
	// second one — GetLatestScanID and ListScanRuns must not see duplicates.
	if err := s.UpsertScanRun(ctx, &ScanRun{ScanID: scanID, DurationMs: 2000, FinalCount: 8}); err != nil {
		t.Fatalf("second UpsertScanRun: %v", err)
	}

	got, err := s.GetScanRun(ctx, scanID)
	if err != nil {
		t.Fatalf("GetScanRun: %v", err)
	}
	if got.DurationMs != 2000 || got.FinalCount != 8 {
		t.Errorf("overwrite must replace the row, got %+v", got)
	}

	runs, err := s.ListScanRuns(ctx, 0)
	if err != nil {
		t.Fatalf("ListScanRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("expected exactly one row after overwrite, got %d", len(runs))
	}
}

func TestStore_ScanRunListNewestFirst(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	older := &ScanRun{ScanID: "sc_old", CreatedAt: 100}
	newer := &ScanRun{ScanID: "sc_new", CreatedAt: 200}
	if err := s.UpsertScanRun(ctx, older); err != nil {
		t.Fatalf("upsert older: %v", err)
	}
	if err := s.UpsertScanRun(ctx, newer); err != nil {
		t.Fatalf("upsert newer: %v", err)
	}

	runs, err := s.ListScanRuns(ctx, 0)
	if err != nil {
		t.Fatalf("ListScanRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(runs))
	}
	if runs[0].ScanID != "sc_new" || runs[1].ScanID != "sc_old" {
		t.Errorf("ListScanRuns must return newest first, got [%s, %s]", runs[0].ScanID, runs[1].ScanID)
	}
}
