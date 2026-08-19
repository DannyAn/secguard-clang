package cli

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestSuppressionIndex_BasicMatch(t *testing.T) {
	findings := []*db.Finding{
		{FilePath: "src/foo.c", LineNumber: 42, RuleID: "CWE-476", Status: "dismissed"},
		{FilePath: "src/bar.c", LineNumber: 10, RuleID: "CWE-787", Status: "confirmed"},
		{FilePath: "src/baz.c", LineNumber: 99, RuleID: "CWE-401", Status: "dismissed"},
	}
	idx := buildSuppressionIndex(findings)
	if idx.suppressedCount() != 2 {
		t.Errorf("expected 2 suppressed, got %d", idx.suppressedCount())
	}
	if !idx.isSuppressed("src/foo.c", 42, "CWE-476") {
		t.Error("expected src/foo.c:42:CWE-476 to be suppressed")
	}
	if !idx.isSuppressed("src/baz.c", 99, "cwe-401") {
		t.Error("expected case-insensitive rule match")
	}
	if idx.isSuppressed("src/foo.c", 43, "CWE-476") {
		t.Error("different line should not match")
	}
	if idx.isSuppressed("src/bar.c", 10, "CWE-787") {
		t.Error("confirmed finding should not be suppressed")
	}
}

func TestSuppressionIndex_Empty(t *testing.T) {
	idx := buildSuppressionIndex(nil)
	if idx.suppressedCount() != 0 {
		t.Errorf("expected 0 suppressed for nil input")
	}
	if idx.isSuppressed("any", 1, "CWE-476") {
		t.Error("nil index should not suppress anything")
	}
}

func TestBaselineIndex_Diff(t *testing.T) {
	findings := []*db.Finding{
		{FilePath: "src/a.c", LineNumber: 5, RuleID: "CWE-476", Status: "confirmed"},
		{FilePath: "src/b.c", LineNumber: 10, RuleID: "CWE-787", Status: "confirmed"},
	}
	bi := &baselineIndex{existing: map[string]bool{}, count: 0}
	for _, f := range findings {
		bi.existing[suppressionKey(f.FilePath, int(f.LineNumber), f.RuleID)] = true
		bi.count++
	}
	if !bi.isExisting("src/a.c", 5, "CWE-476") {
		t.Error("expected src/a.c:5 to be existing in baseline")
	}
	if bi.isExisting("src/c.c", 1, "CWE-476") {
		t.Error("new finding should not be in baseline")
	}
}

func TestFilterSuppressedCandidates(t *testing.T) {
	items := []planner.EvidenceItem{
		{Target: planner.TargetInfo{File: "a.c", Line: 1, Function: "f1"}},
		{Target: planner.TargetInfo{File: "b.c", Line: 2, Function: "f2"}},
		{Target: planner.TargetInfo{File: "c.c", Line: 3, Function: "f3"}},
	}
	sup := &suppressionIndex{
		byKey: map[string]bool{suppressionKey("a.c", 1, "CWE-476"): true},
		count: 1,
	}
	baseline := &baselineIndex{
		existing: map[string]bool{suppressionKey("b.c", 2, "CWE-476"): true},
		count:    1,
	}
	kept, suppressed, baselineExisting := filterSuppressedCandidates(items, "CWE-476", sup, baseline)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
	if suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", suppressed)
	}
	if baselineExisting != 1 {
		t.Errorf("expected 1 baseline existing, got %d", baselineExisting)
	}
	if kept[0].Target.File != "c.c" {
		t.Errorf("expected kept to be c.c, got %s", kept[0].Target.File)
	}
}