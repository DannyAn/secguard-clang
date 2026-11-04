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
func TestStore_ScanRunCompletionStateDefault(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	scanID := "sc_2026-11-04_200000_aaaaaa"
	if err := s.UpsertScanRun(ctx, &ScanRun{ScanID: scanID, FinalCount: 3}); err != nil {
		t.Fatalf("UpsertScanRun: %v", err)
	}

	got, err := s.GetScanRun(ctx, scanID)
	if err != nil {
		t.Fatalf("GetScanRun: %v", err)
	}
	if got.CompletionState != "running" {
		t.Errorf("new scan_run must default to completion_state='running', got %q", got.CompletionState)
	}
}

func TestStore_SetScanRunCompletionState(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	scanID := "sc_2026-11-04_200000_bbbbbb"
	if err := s.UpsertScanRun(ctx, &ScanRun{ScanID: scanID}); err != nil {
		t.Fatalf("UpsertScanRun: %v", err)
	}

	for _, state := range []string{"complete", "failed", "incomplete", "limited"} {
		if err := s.SetScanRunCompletionState(ctx, scanID, state); err != nil {
			t.Fatalf("SetScanRunCompletionState(%q): %v", state, err)
		}
		got, err := s.GetScanRun(ctx, scanID)
		if err != nil {
			t.Fatalf("GetScanRun: %v", err)
		}
		if got.CompletionState != state {
			t.Errorf("after SetScanRunCompletionState(%q): got %q", state, got.CompletionState)
		}
	}
}

func TestStore_MarkStaleRunningAsFailed(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	running1 := &ScanRun{ScanID: "sc_2026-11-04_200000_cccccc"}
	running2 := &ScanRun{ScanID: "sc_2026-11-04_200100_dddddd"}
	complete := &ScanRun{ScanID: "sc_2026-11-04_200200_eeeeee", CompletionState: "complete"}
	for _, r := range []*ScanRun{running1, running2, complete} {
		if err := s.UpsertScanRun(ctx, r); err != nil {
			t.Fatalf("UpsertScanRun %s: %v", r.ScanID, err)
		}
	}

	n, err := s.MarkStaleRunningAsFailed(ctx)
	if err != nil {
		t.Fatalf("MarkStaleRunningAsFailed: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 stale running scans marked failed, got %d", n)
	}

	for _, scanID := range []string{running1.ScanID, running2.ScanID} {
		got, err := s.GetScanRun(ctx, scanID)
		if err != nil {
			t.Fatalf("GetScanRun: %v", err)
		}
		if got.CompletionState != "failed" {
			t.Errorf("scan %s must be 'failed' after mark-stale, got %q", scanID, got.CompletionState)
		}
	}

	got, err := s.GetScanRun(ctx, complete.ScanID)
	if err != nil {
		t.Fatalf("GetScanRun: %v", err)
	}
	if got.CompletionState != "complete" {
		t.Errorf("already-complete scan must be untouched, got %q", got.CompletionState)
	}

	n2, err := s.MarkStaleRunningAsFailed(ctx)
	if err != nil {
		t.Fatalf("second MarkStaleRunningAsFailed: %v", err)
	}
	if n2 != 0 {
		t.Errorf("no running scans left, expected 0, got %d", n2)
	}
}

func TestStore_IncompleteTasksCRUD(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	scanID := "sc_2026-11-04_200300_ffffff"
	tasks := []*ScanIncompleteTask{
		{ScanID: scanID, Phase: "planner", FunctionID: 42, FilePath: "src/foo.c", Scale: 100, Reason: "timeout", Detail: "plan stage exceeded 30s"},
		{ScanID: scanID, Phase: "detector", FunctionID: 7, FilePath: "src/bar.c", Reason: "panic"},
		{ScanID: scanID, Phase: "graph", Reason: "oom", Detail: "CFG cache full"},
	}
	for _, task := range tasks {
		if err := s.InsertIncompleteTask(ctx, task); err != nil {
			t.Fatalf("InsertIncompleteTask: %v", err)
		}
	}

	got, err := s.ListIncompleteTasks(ctx, scanID)
	if err != nil {
		t.Fatalf("ListIncompleteTasks: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 incomplete tasks, got %d", len(got))
	}

	if got[0].Phase != "planner" || got[0].FunctionID != 42 || got[0].FilePath != "src/foo.c" || got[0].Reason != "timeout" {
		t.Errorf("task 0 round-trip mismatch: %+v", got[0])
	}
	if got[1].Phase != "detector" || got[1].FunctionID != 7 || got[1].Reason != "panic" {
		t.Errorf("task 1 round-trip mismatch: %+v", got[1])
	}
	if got[2].Phase != "graph" || got[2].Reason != "oom" || got[2].Detail != "CFG cache full" {
		t.Errorf("task 2 round-trip mismatch: %+v", got[2])
	}

	other, err := s.ListIncompleteTasks(ctx, "sc_nonexistent")
	if err != nil {
		t.Fatalf("ListIncompleteTasks for nonexistent scan: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("expected 0 tasks for nonexistent scan, got %d", len(other))
	}
}
