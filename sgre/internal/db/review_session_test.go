//go:build !nosqlite

package db

import (
	"context"
	"testing"
)

func TestStore_UpsertReviewSession_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	r := &ReviewSession{
		ReviewID: "pr_abc1234_def5678",
		Kind:     "pr",
		BaseRef:  "origin/main",
		HeadRef:  "HEAD",
		BaseSHA:  "abc1234",
		HeadSHA:  "def5678",
		Status:   "running",
	}
	if err := s.UpsertReviewSession(ctx, r); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	r.Status = "done"
	r.ChangedFiles = `[{"Path":"a.c","Status":"M","Lines":[15]}]`
	if err := s.UpsertReviewSession(ctx, r); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := s.GetReviewSessionByID(ctx, "pr_abc1234_def5678")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("review session not found")
	}
	if got.Status != "running" {
		t.Errorf("re-upsert must not overwrite status (only --review-status mutates): got %q", got.Status)
	}
	if got.ChangedFiles != `[{"Path":"a.c","Status":"M","Lines":[15]}]` {
		t.Errorf("changed_files should update: got %q", got.ChangedFiles)
	}
}

func TestStore_ListFingerprintsExcludingScanID(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	for _, f := range []*Finding{
		{RuleID: "CWE-476", Severity: "high", Status: "confirmed", FilePath: "a.c", LineNumber: 9, FunctionName: "f", Fingerprint: "fp1", ScanID: "sc_1"},
		{RuleID: "CWE-787", Severity: "high", Status: "confirmed", FilePath: "a.c", LineNumber: 15, FunctionName: "g", Fingerprint: "fp2", ScanID: "sc_1"},
		{RuleID: "CWE-476", Severity: "high", Status: "confirmed", FilePath: "a.c", LineNumber: 9, FunctionName: "f", Fingerprint: "fp1", ScanID: "pr_x_y"},
	} {
		if _, err := s.InsertFinding(ctx, f); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}

	// Excluding pr_x_y leaves fp1 (from sc_1) and fp2.
	set, err := s.ListFingerprintsExcludingScanID(ctx, "pr_x_y")
	if err != nil {
		t.Fatalf("list fingerprints: %v", err)
	}
	if len(set) != 2 || !set["fp1"] || !set["fp2"] {
		t.Errorf("expected {fp1, fp2}, got %v", set)
	}

	// Excluding nothing returns both.
	all, err := s.ListFingerprintsExcludingScanID(ctx, "")
	if err != nil {
		t.Fatalf("list fingerprints (no exclude): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 distinct fingerprints, got %v", all)
	}
}

func TestSchemaDDL_ContainsReviewSessionsTable(t *testing.T) {
	if !schemaHasTable(SchemaDDL, "review_sessions") {
		t.Error("SchemaDDL missing review_sessions table")
	}
}
