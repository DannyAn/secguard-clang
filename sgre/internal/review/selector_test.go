package review

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

type fakeFinder struct {
	unreviewed []*db.Finding
	gotRuleIDs []string
}

func (f *fakeFinder) ListAutoConfirmedForReview(ctx context.Context, scanID string, ruleIDs []string, limit int) ([]*db.Finding, error) {
	f.gotRuleIDs = ruleIDs
	return f.unreviewed, nil
}

func TestSelector_SelectsUnreviewed(t *testing.T) {
	f := &fakeFinder{unreviewed: []*db.Finding{{ID: 1, ScanID: "s"}}}
	s := NewTargetSelector(f)
	opts := RunOptions{ScanSourceRev: "rev", ReviewedRevision: "rev"}

	targets, err := s.SelectTargets(context.Background(), RunFilter{ScanID: "s"}, opts)
	if err != nil {
		t.Fatalf("SelectTargets: %v", err)
	}
	if len(targets) != 1 || targets[0].Finding.ID != 1 {
		t.Errorf("should select unreviewed finding 1, got %+v", targets)
	}
}

func TestSelector_RevisionVerified(t *testing.T) {
	f := &fakeFinder{unreviewed: []*db.Finding{{ID: 1, ScanID: "s"}}}
	s := NewTargetSelector(f)

	verified := RunOptions{ScanSourceRev: "rev", ReviewedRevision: "rev", TreeDirty: false}
	targets, _ := s.SelectTargets(context.Background(), RunFilter{}, verified)
	if !targets[0].RevisionVerified {
		t.Error("matching clean revision should be verified")
	}

	mismatch := RunOptions{ScanSourceRev: "rev", ReviewedRevision: "other"}
	targets, _ = s.SelectTargets(context.Background(), RunFilter{}, mismatch)
	if targets[0].RevisionVerified {
		t.Error("mismatched revision should not be verified")
	}

	empty := RunOptions{}
	targets, _ = s.SelectTargets(context.Background(), RunFilter{}, empty)
	if targets[0].RevisionVerified {
		t.Error("empty revision should not be verified")
	}
}

func TestVulnTypesToRuleIDs_CategoryCWEs(t *testing.T) {
	ids, err := vulnTypesToRuleIDs([]string{"injection"})
	if err != nil {
		t.Fatalf("vulnTypesToRuleIDs: %v", err)
	}
	// injection covers multiple CWEs via CategoryCWEs; the canonical CWE-78
	// alone would silently drop sql/argument/crlf injection findings.
	if len(ids) < 2 {
		t.Errorf("injection should map to multiple rule ids, got %v", ids)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen["CWE-78"] {
		t.Errorf("expected CWE-78, got %v", ids)
	}
}

func TestVulnTypesToRuleIDs_UnknownType(t *testing.T) {
	if _, err := vulnTypesToRuleIDs([]string{"not-a-type"}); err == nil {
		t.Fatal("expected error for unknown vuln type")
	}
}

func TestVulnTypesToRuleIDs_Empty(t *testing.T) {
	ids, err := vulnTypesToRuleIDs(nil)
	if err != nil {
		t.Fatalf("vulnTypesToRuleIDs: %v", err)
	}
	if ids != nil {
		t.Errorf("nil input should map to nil rule ids, got %v", ids)
	}
}
