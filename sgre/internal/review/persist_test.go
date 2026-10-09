package review

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestMergeProperties_PreservesAutoConfirmEvidence(t *testing.T) {
	existing := `{"auto_confirm_evidence":[{"type":"null_source"}]}`
	reviewJSON := `{"verdict":"false_positive"}`
	merged, err := MergeProperties(existing, reviewJSON)
	if err != nil {
		t.Fatalf("MergeProperties: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(merged), &raw); err != nil {
		t.Fatalf("Unmarshal merged: %v", err)
	}
	if _, ok := raw["auto_confirm_evidence"]; !ok {
		t.Error("auto_confirm_evidence should be preserved in merged properties")
	}
	if _, ok := raw["review"]; !ok {
		t.Error("review should be present in merged properties")
	}
}

func TestMergeProperties_OverwritesReview(t *testing.T) {
	existing := `{"review":{"verdict":"ai_confirmed"}}`
	merged, err := MergeProperties(existing, `{"verdict":"false_positive"}`)
	if err != nil {
		t.Fatalf("MergeProperties: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal([]byte(merged), &raw)
	var review map[string]string
	json.Unmarshal(raw["review"], &review)
	if review["verdict"] != "false_positive" {
		t.Errorf("review[verdict] = %q, want false_positive", review["verdict"])
	}
}

func TestMergeProperties_EmptyExisting(t *testing.T) {
	merged, err := MergeProperties("", `{"verdict":"x"}`)
	if err != nil {
		t.Fatalf("MergeProperties: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal([]byte(merged), &raw)
	if _, ok := raw["review"]; !ok {
		t.Error("review key should exist")
	}
}

func TestMergeProperties_CorruptExisting(t *testing.T) {
	if _, err := MergeProperties(`{invalid json`, `{"verdict":"x"}`); err == nil {
		t.Fatal("expected error for corrupt existing properties")
	}
}

type fakeReviewWriter struct {
	lastID         int64
	lastStatus     string
	lastReasoning  string
	lastProperties string
}

func (f *fakeReviewWriter) UpdateFindingReviewWithProperties(ctx context.Context, id int64, reviewStatus, reviewReasoning, properties string) error {
	f.lastID = id
	f.lastStatus = reviewStatus
	f.lastReasoning = reviewReasoning
	f.lastProperties = properties
	return nil
}

func TestPersist_WritesVerdictAndPreservesEvidence(t *testing.T) {
	w := &fakeReviewWriter{}
	p := NewResultPersister(w)
	target := ReviewTarget{
		Finding: &db.Finding{
			ID:         9,
			Properties: `{"auto_confirm_evidence":[{"type":"null_source"}]}`,
		},
		ScanSourceRev:    "rev1",
		ReviewedRev:      "rev1",
		RevisionVerified: true,
	}
	verdict := &Verdict{
		FindingID:             9,
		Verdict:               VerdictFalsePositive,
		Rationale:             "guard exists",
		ContradictingEvidence: []string{"line 3 checks p != NULL"},
		Confidence:            0.8,
	}
	audit := &ReviewAudit{
		ModelProvider:    "test",
		Model:            "m1",
		PromptVersion:    "p1",
		SchemaVersion:    "s1",
		SourceRevision:   "rev1",
		ReviewedRevision: "rev1",
		RevisionVerified: true,
		DurationMs:       123,
		ReviewedAt:       1700000000,
	}
	if err := p.Persist(context.Background(), target, verdict, audit); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if w.lastID != 9 {
		t.Errorf("lastID = %d, want 9", w.lastID)
	}
	if w.lastStatus != VerdictFalsePositive {
		t.Errorf("review_status = %q, want false_positive", w.lastStatus)
	}
	if w.lastReasoning != "guard exists" {
		t.Errorf("review_reasoning = %q", w.lastReasoning)
	}

	var props map[string]json.RawMessage
	if err := json.Unmarshal([]byte(w.lastProperties), &props); err != nil {
		t.Fatalf("properties not valid JSON: %v", err)
	}
	if _, ok := props["auto_confirm_evidence"]; !ok {
		t.Error("auto_confirm_evidence lost during persist")
	}
	var review map[string]interface{}
	if err := json.Unmarshal(props["review"], &review); err != nil {
		t.Fatalf("review blob not valid JSON: %v", err)
	}
	if review["verdict"] != "false_positive" {
		t.Errorf("review.verdict = %v, want false_positive", review["verdict"])
	}
	if ce, ok := review["contradicting_evidence"].([]interface{}); !ok || len(ce) != 1 {
		t.Errorf("contradicting_evidence lost: %v", review["contradicting_evidence"])
	}
}

func TestPersist_RejectsReviewError(t *testing.T) {
	w := &fakeReviewWriter{}
	p := NewResultPersister(w)
	target := ReviewTarget{Finding: &db.Finding{ID: 1}}
	v := &Verdict{FindingID: 1, Verdict: VerdictReviewError, Rationale: "http 500"}
	if err := p.Persist(context.Background(), target, v, &ReviewAudit{}); err == nil {
		t.Fatal("review_error must never be persisted as a verdict")
	}
	if w.lastStatus != "" {
		t.Errorf("review_error should not write review_status, got %q", w.lastStatus)
	}
}
