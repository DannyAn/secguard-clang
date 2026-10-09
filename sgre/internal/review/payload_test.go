package review

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func newBuilder(root string) *PayloadBuilder {
	return NewPayloadBuilder(root, "p1", "s1")
}

func TestBuildPayload_NilFinding(t *testing.T) {
	b := newBuilder("/tmp")
	_, err := b.BuildPayload(context.Background(), ReviewTarget{})
	if err == nil {
		t.Fatal("expected error for nil finding")
	}
}

func TestBuildPayload_EmptyRevisionAllowed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.c"), []byte("x\n"), 0644)
	b := newBuilder(dir)
	f := &db.Finding{ID: 1, RuleID: "CWE-476", FilePath: "a.c", LineNumber: 1}
	payload, err := b.BuildPayload(context.Background(), ReviewTarget{Finding: f})
	if err != nil {
		t.Fatalf("BuildPayload with empty revision should not hard-fail: %v", err)
	}
	if payload.Source.Revision != "" {
		t.Errorf("Revision = %q, want empty", payload.Source.Revision)
	}
	if payload.Source.RevisionVerified {
		t.Error("RevisionVerified should be false for empty source revision")
	}
}

func TestBuildPayload_MetaComplete(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "test.c")
	os.WriteFile(srcFile, []byte("int main() {\n  int *p = 0;\n  return *p;\n}\n"), 0644)

	b := newBuilder(dir)
	f := &db.Finding{
		ID:           42,
		RuleID:       "CWE-476",
		Status:       "auto-confirmed",
		Severity:     "high",
		Summary:      "null dereference",
		FilePath:     "test.c",
		LineNumber:   3,
		FunctionName: "main",
		Fingerprint:  "abc",
	}
	payload, err := b.BuildPayload(context.Background(), ReviewTarget{Finding: f, ScanSourceRev: "rev123", ReviewedRev: "rev123", RevisionVerified: true})
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if payload.SchemaVersion != "1" {
		t.Errorf("SchemaVersion = %q, want 1", payload.SchemaVersion)
	}
	if payload.Finding.FindingID != 42 {
		t.Errorf("FindingID = %d, want 42", payload.Finding.FindingID)
	}
	if payload.Finding.File != "test.c" {
		t.Errorf("File = %q, want test.c", payload.Finding.File)
	}
	if payload.Source.Revision != "rev123" {
		t.Errorf("Revision = %q, want rev123", payload.Source.Revision)
	}
	if !payload.Source.RevisionVerified {
		t.Error("RevisionVerified should be true")
	}
	if payload.Source.CodeExcerpt == "" {
		t.Error("CodeExcerpt should not be empty")
	}
	if !strings.Contains(payload.ReviewID, "rv_42_rev123_p1_s1") {
		t.Errorf("ReviewID = %q, want deterministic rv_42_rev123_p1_s1", payload.ReviewID)
	}
}

func TestBuildPayload_AbsoluteFilePath(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "test.c")
	os.WriteFile(srcFile, []byte("line1\nline2\nline3\n"), 0644)

	b := newBuilder(dir)
	// Findings written by the pipeline carry ABSOLUTE paths; the payload
	// builder must resolve them as-is, not join them under the project root.
	f := &db.Finding{ID: 1, RuleID: "CWE-476", FilePath: srcFile, LineNumber: 2}
	payload, err := b.BuildPayload(context.Background(), ReviewTarget{Finding: f, ScanSourceRev: "rev"})
	if err != nil {
		t.Fatalf("BuildPayload with absolute path: %v", err)
	}
	if payload.Source.CodeExcerpt == "" || !strings.Contains(payload.Source.CodeExcerpt, "line2") {
		t.Errorf("CodeExcerpt = %q, want to contain line2", payload.Source.CodeExcerpt)
	}
}

func TestBuildPayload_EvidenceFromProperties(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.c"), []byte("x\n"), 0644)

	b := newBuilder(dir)
	props := `{"auto_confirm_evidence":[{"type":"null_source","role":"seed","detail":"assignment from 0"}]}`
	f := &db.Finding{
		ID:         1,
		RuleID:     "CWE-476",
		Status:     "auto-confirmed",
		FilePath:   "test.c",
		LineNumber: 1,
		Properties: props,
	}
	payload, err := b.BuildPayload(context.Background(), ReviewTarget{Finding: f, ScanSourceRev: "rev"})
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if payload.Evidence.EvidenceSource != EvidenceSourceAutoConfirm {
		t.Errorf("EvidenceSource = %q, want %q", payload.Evidence.EvidenceSource, EvidenceSourceAutoConfirm)
	}
	if len(payload.Evidence.TriggerEvidence) != 1 {
		t.Fatalf("TriggerEvidence len = %d, want 1", len(payload.Evidence.TriggerEvidence))
	}
	if payload.Evidence.TriggerEvidence[0].Type != "null_source" {
		t.Errorf("Type = %q, want null_source", payload.Evidence.TriggerEvidence[0].Type)
	}
}

func TestBuildPayload_EvidenceFallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.c"), []byte("x\n"), 0644)

	b := newBuilder(dir)
	f := &db.Finding{ID: 1, RuleID: "CWE-476", FilePath: "test.c", LineNumber: 1, Summary: "null deref of p"}
	payload, err := b.BuildPayload(context.Background(), ReviewTarget{Finding: f, ScanSourceRev: "rev"})
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if payload.Evidence.EvidenceSource != EvidenceSourceFallback {
		t.Errorf("EvidenceSource = %q, want %q", payload.Evidence.EvidenceSource, EvidenceSourceFallback)
	}
	if len(payload.Evidence.TriggerEvidence) != 1 || payload.Evidence.TriggerEvidence[0].Detail != "null deref of p" {
		t.Errorf("TriggerEvidence = %+v, want summary fallback", payload.Evidence.TriggerEvidence)
	}
}

func TestBuildPayload_EvidenceMissing(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.c"), []byte("x\n"), 0644)

	b := newBuilder(dir)
	f := &db.Finding{ID: 1, RuleID: "CWE-476", FilePath: "test.c", LineNumber: 1}
	payload, err := b.BuildPayload(context.Background(), ReviewTarget{Finding: f, ScanSourceRev: "rev"})
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if payload.Evidence.EvidenceSource != EvidenceSourceMissing {
		t.Errorf("EvidenceSource = %q, want %q", payload.Evidence.EvidenceSource, EvidenceSourceMissing)
	}
}

func TestReadSourceExcerpt_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	b := newBuilder(dir)
	_, _, err := b.readSourceExcerpt("../../../etc/passwd", 1)
	if err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("expected path traversal error, got %v", err)
	}
}

func TestReadSourceExcerpt_AbsoluteMissing(t *testing.T) {
	dir := t.TempDir()
	b := newBuilder(dir)
	_, _, err := b.readSourceExcerpt(filepath.Join(dir, "does-not-exist.c"), 1)
	if err == nil {
		t.Fatal("expected error for missing absolute file")
	}
}

func TestReadSourceExcerpt_NormalPath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "src.c"), []byte("line1\nline2\nline3\n"), 0644)
	b := newBuilder(dir)
	excerpt, truncated, err := b.readSourceExcerpt("src.c", 2)
	if err != nil {
		t.Fatalf("readSourceExcerpt: %v", err)
	}
	if excerpt == "" {
		t.Error("excerpt should not be empty")
	}
	if truncated {
		t.Error("should not be truncated for small file")
	}
}
