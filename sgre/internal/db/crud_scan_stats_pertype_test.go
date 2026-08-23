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

	for i := 0; i < 10; i++ {
		if _, err := s.UpsertFinding(ctx, &Finding{RuleID: "CWE-476", Severity: "low", Status: "dismissed", FilePath: "a.c", LineNumber: i + 1, FunctionName: "f", ScanID: scanID}); err != nil {
			t.Fatalf("insert finding %d: %v", i, err)
		}
	}
	for i := 0; i < 5; i++ {
		if _, err := s.UpsertFinding(ctx, &Finding{RuleID: "CWE-787", Severity: "high", Status: "confirmed", FilePath: "b.c", LineNumber: i + 1, FunctionName: "g", ScanID: scanID}); err != nil {
			t.Fatalf("insert finding %d: %v", i, err)
		}
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
	}{
		{"null-deref", "CWE-476", 10, 10, "done"},
		{"buffer-overflow", "CWE-787", 20, 5, "in-progress"},
		{"crypto-misuse", "CWE-327", 8, 0, "pending"},
		{"divide-by-zero", "CWE-369", 0, 0, "done"},
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

func TestInferTerminalState(t *testing.T) {
	cases := []struct {
		candidate, written int
		want               string
	}{
		{0, 0, "done"},
		{10, 10, "done"},
		{10, 5, "in-progress"},
		{10, 0, "pending"},
		{1, 0, "pending"},
		{1, 1, "done"},
		{10, 12, "done"},
	}
	for _, c := range cases {
		if got := inferTerminalState(c.candidate, c.written); got != c.want {
			t.Errorf("inferTerminalState(%d, %d) = %q, want %q", c.candidate, c.written, got, c.want)
		}
	}
}
