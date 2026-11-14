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
	// Legacy empty-variable dismissals match any variable at the location.
	if !idx.isSuppressed("src/foo.c", 42, "CWE-476", "p") {
		t.Error("expected src/foo.c:42:CWE-476 to be suppressed")
	}
	if !idx.isSuppressed("src/baz.c", 99, "cwe-401", "q") {
		t.Error("expected case-insensitive rule match")
	}
	if idx.isSuppressed("src/foo.c", 43, "CWE-476", "p") {
		t.Error("different line should not match")
	}
	if idx.isSuppressed("src/bar.c", 10, "CWE-787", "p") {
		t.Error("confirmed finding should not be suppressed")
	}
}

func TestSuppressionIndex_Empty(t *testing.T) {
	idx := buildSuppressionIndex(nil)
	if idx.suppressedCount() != 0 {
		t.Errorf("expected 0 suppressed for nil input")
	}
	if idx.isSuppressed("any", 1, "CWE-476", "p") {
		t.Error("nil index should not suppress anything")
	}
}

func TestSuppressionIndex_SameLocationDifferentVariables(t *testing.T) {
	// Two null-deref candidates on the same line but different variables. A
	// dismissed finding names only `p`, so `p` must be suppressed while `q`
	// stays visible — the finding identity includes variable.
	findings := []*db.Finding{
		{FilePath: "src/a.c", LineNumber: 3, RuleID: "CWE-476", Variable: "p", Status: "dismissed"},
	}
	idx := buildSuppressionIndex(findings)
	if !idx.isSuppressed("src/a.c", 3, "CWE-476", "p") {
		t.Error("expected variable p at src/a.c:3 to be suppressed")
	}
	if idx.isSuppressed("src/a.c", 3, "CWE-476", "q") {
		t.Error("dismissing p must not suppress the sibling variable q at the same line")
	}
	if idx.isSuppressed("src/a.c", 3, "CWE-476", "") {
		t.Error("an empty variable must not match a variable-specific dismissal")
	}
}

func TestBaselineIndex_Diff(t *testing.T) {
	findings := []*db.Finding{
		{FilePath: "src/a.c", LineNumber: 5, RuleID: "CWE-476", Status: "confirmed", Variable: "p"},
		{FilePath: "src/b.c", LineNumber: 10, RuleID: "CWE-787", Status: "confirmed", Variable: "q"},
	}
	bi := &baselineIndex{existing: map[string]bool{}, wildcard: map[string]bool{}, count: 0}
	for _, f := range findings {
		if f.Variable == "" {
			bi.wildcard[suppressionLocationKey(f.FilePath, int(f.LineNumber), f.RuleID)] = true
		} else {
			bi.existing[suppressionKey(f.FilePath, int(f.LineNumber), f.RuleID, f.Variable)] = true
		}
		bi.count++
	}
	if !bi.isExisting("src/a.c", 5, "CWE-476", "p") {
		t.Error("expected src/a.c:5 to be existing in baseline")
	}
	if bi.isExisting("src/a.c", 5, "CWE-476", "q") {
		t.Error("baseline variable p must not swallow variable q at the same line")
	}
	if bi.isExisting("src/c.c", 1, "CWE-476", "p") {
		t.Error("new finding should not be in baseline")
	}
}

func TestFilterSuppressedCandidates(t *testing.T) {
	items := []planner.EvidenceItem{
		{Target: planner.TargetInfo{File: "a.c", Line: 1, Function: "f1", Variable: "p"}},
		{Target: planner.TargetInfo{File: "b.c", Line: 2, Function: "f2", Variable: "q"}},
		{Target: planner.TargetInfo{File: "c.c", Line: 3, Function: "f3", Variable: "r"}},
	}
	sup := &suppressionIndex{
		byKey:    map[string]bool{suppressionKey("a.c", 1, "CWE-476", "p"): true},
		wildcard: map[string]bool{},
		count:    1,
	}
	baseline := &baselineIndex{
		existing: map[string]bool{suppressionKey("b.c", 2, "CWE-476", "q"): true},
		wildcard: map[string]bool{},
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
