//go:build !nosqlite

package db

import (
	"context"
	"testing"
)

func TestListPerTypeStatus_TerminalStates(t *testing.T) {
	s := NewTestStore(t)
	ctx := context.Background()
	scanID := "sc_test_pertype_1"

	cweForType := func(vt string) string {
		m := map[string]string{
			"null-deref":      "CWE-476",
			"buffer-overflow": "CWE-787",
			"crypto-misuse":   "CWE-327",
			"divide-by-zero":  "CWE-369",
		}
		return m[vt]
	}

	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: scanID, VulnType: "null-deref", FinalCount: 10}); err != nil {
		t.Fatalf("insert scanstat null-deref: %v", err)
	}
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: scanID, VulnType: "buffer-overflow", FinalCount: 20}); err != nil {
		t.Fatalf("insert scanstat buffer-overflow: %v", err)
	}
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: scanID, VulnType: "crypto-misuse", FinalCount: 8}); err != nil {
		t.Fatalf("insert scanstat crypto-misuse: %v", err)
	}
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: scanID, VulnType: "divide-by-zero", FinalCount: 0}); err != nil {
		t.Fatalf("insert scanstat divide-by-zero: %v", err)
	}

	for i := 0; i < 5; i++ {
		if _, err := s.UpsertFinding(ctx, &Finding{RuleID: "CWE-787", Severity: "high", Status: "confirmed", FilePath: "b.c", LineNumber: i + 1, FunctionName: "g", ScanID: scanID}); err != nil {
			t.Fatalf("insert finding %d: %v", i, err)
		}
	}
	if err := s.MarkAIStageDone(ctx, scanID, "null-deref"); err != nil {
		t.Fatalf("mark ai_stage_done null-deref: %v", err)
	}

	statuses, err := s.ListPerTypeStatus(ctx, scanID, cweForType)
	if err != nil {
		t.Fatalf("ListPerTypeStatus: %v", err)
	}

	byType := map[string]*PerTypeStatus{}
	for _, st := range statuses {
		byType[st.VulnType] = st
	}

	cases := []struct {
		vt        string
		cwe       string
		candidate int
		written   int
		terminal  string
		aiStage   string
	}{
		{"null-deref", "CWE-476", 10, 0, "done", "done"},
		{"buffer-overflow", "CWE-787", 20, 5, "in-progress", "pending"},
		{"crypto-misuse", "CWE-327", 8, 0, "pending", "pending"},
		{"divide-by-zero", "CWE-369", 0, 0, "done", "pending"},
	}
	for _, c := range cases {
		st, ok := byType[c.vt]
		if !ok {
			t.Errorf("type %q missing from result", c.vt)
			continue
		}
		if st.CWE != c.cwe {
			t.Errorf("%s: CWE = %q, want %q", c.vt, st.CWE, c.cwe)
		}
		if st.CandidateCount != c.candidate {
			t.Errorf("%s: candidate = %d, want %d", c.vt, st.CandidateCount, c.candidate)
		}
		if st.WrittenCount != c.written {
			t.Errorf("%s: written = %d, want %d", c.vt, st.WrittenCount, c.written)
		}
		if st.TerminalState != c.terminal {
			t.Errorf("%s: terminal = %q, want %q", c.vt, st.TerminalState, c.terminal)
		}
		if st.AIStageStatus != c.aiStage {
			t.Errorf("%s: ai_stage_status = %q, want %q", c.vt, st.AIStageStatus, c.aiStage)
		}
	}
}

func TestListPerTypeStatus_EmptyScanID(t *testing.T) {
	s := NewTestStore(t)
	ctx := context.Background()
	statuses, err := s.ListPerTypeStatus(ctx, "nonexistent_scan", func(string) string { return "" })
	if err != nil {
		t.Fatalf("expected no error for empty scan, got %v", err)
	}
	if len(statuses) != 0 {
		t.Errorf("expected 0 statuses for nonexistent scan, got %d", len(statuses))
	}
}

func TestListPerTypeStatus_NilCweMapper(t *testing.T) {
	s := NewTestStore(t)
	ctx := context.Background()
	scanID := "sc_test_nil_mapper"
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: scanID, VulnType: "null-deref", FinalCount: 5}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	statuses, err := s.ListPerTypeStatus(ctx, scanID, nil)
	if err != nil {
		t.Fatalf("nil mapper: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].CWE != "" {
		t.Errorf("nil mapper should yield empty CWE, got %q", statuses[0].CWE)
	}
	if statuses[0].TerminalState != "pending" {
		t.Errorf("5 candidates 0 written = pending, got %q", statuses[0].TerminalState)
	}
}

func TestInferTerminalStateByAIStageStatus(t *testing.T) {
	cases := []struct {
		aiStage   string
		candidate int
		written   int
		want      string
	}{
		{"done", 0, 0, "done"},
		{"done", 10, 5, "done"},
		{"failed", 10, 5, "failed"},
		{"pending", 0, 0, "done"},
		{"pending", 10, 10, "in-progress"},
		{"pending", 10, 5, "in-progress"},
		{"pending", 10, 0, "pending"},
		{"pending", 1, 0, "pending"},
		{"pending", 1, 1, "in-progress"},
		{"", 0, 0, "done"},
		{"", 10, 0, "pending"},
		{"", 10, 5, "in-progress"},
	}
	for _, c := range cases {
		if got := inferTerminalStateByAIStageStatus(c.aiStage, c.candidate, c.written); got != c.want {
			t.Errorf("inferTerminalStateByAIStageStatus(%q, %d, %d) = %q, want %q", c.aiStage, c.candidate, c.written, got, c.want)
		}
	}
}
func TestMarkAIStageDone(t *testing.T) {
	s := NewTestStore(t)
	ctx := context.Background()
	scanID := "sc_mark_done_1"

	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: scanID, VulnType: "null-deref", FinalCount: 5}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.InsertScanStat(ctx, &ScanStat{ScanID: scanID, VulnType: "buffer-overflow", FinalCount: 3}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := s.MarkAIStageDone(ctx, scanID, "null-deref"); err != nil {
		t.Fatalf("mark done: %v", err)
	}

	stats, err := s.ListScanStats(ctx, scanID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byType := map[string]*ScanStat{}
	for _, st := range stats {
		byType[st.VulnType] = st
	}
	if byType["null-deref"].AIStageStatus != "done" {
		t.Errorf("null-deref ai_stage_status = %q, want done", byType["null-deref"].AIStageStatus)
	}
	if byType["buffer-overflow"].AIStageStatus != "pending" {
		t.Errorf("buffer-overflow ai_stage_status = %q, want pending", byType["buffer-overflow"].AIStageStatus)
	}

	if err := s.MarkAIStageDone(ctx, scanID, "null-deref"); err != nil {
		t.Fatalf("idempotent re-mark should succeed: %v", err)
	}

	if err := s.MarkAIStageDone(ctx, scanID, "nonexistent"); err == nil {
		t.Errorf("mark done on nonexistent type should error")
	}
}
