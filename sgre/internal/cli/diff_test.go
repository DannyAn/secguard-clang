package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/git"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestReviewIDFor(t *testing.T) {
	id := reviewIDFor("pr", "abcdef1234567890", "0123456789abcdef")
	if id != "pr_abcdef1_0123456" {
		t.Errorf("unexpected review id: %q", id)
	}
	if reviewIDFor("diff", "x", "y") != "diff_x_y" {
		t.Errorf("short sha should not pad: %q", reviewIDFor("diff", "x", "y"))
	}
}

func TestBuildChangedLines(t *testing.T) {
	files := []git.FileDiff{
		{Path: "a.c", Status: "M", Lines: []int{3, 9, 15}},
		{Path: "src/b.c", Status: "A", Lines: []int{1, 2}},
		{Path: "gone.c", Status: "D", Lines: []int{1}},
	}
	root := t.TempDir()
	sets := buildChangedLines(files, root)

	aKey := filepath.Join(root, "a.c")
	if set, ok := sets[aKey]; !ok || !set[9] || !set[15] {
		t.Errorf("a.c lines wrong: %v", sets[aKey])
	}
	bKey := filepath.Join(root, "src", "b.c")
	if set, ok := sets[bKey]; !ok || len(set) != 2 {
		t.Errorf("b.c lines wrong: %v", sets[bKey])
	}
	if _, ok := sets[filepath.Join(root, "gone.c")]; ok {
		t.Error("deleted file should be skipped")
	}
}

func TestScopeToDiffLines(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.c")
	lineSets := map[string]map[int]bool{
		a: {9: true, 15: true},
	}
	items := []planner.EvidenceItem{
		{Target: planner.TargetInfo{File: a, Line: 15}},                    // sink on changed line
		{Target: planner.TargetInfo{File: a, Line: 500}, SourceLine: 9},    // flow source on changed line
		{Target: planner.TargetInfo{File: a, Line: 42}},                    // unchanged
		{Target: planner.TargetInfo{File: filepath.Join(root, "b.c"), Line: 15}}, // unchanged file
	}
	kept := scopeToDiffLines(items, lineSets)
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(kept))
	}
	if kept[0].Target.Line != 15 || kept[1].Target.Line != 500 {
		t.Errorf("wrong kept candidates: %+v", kept)
	}
}

func TestFilterByBaselineFingerprint(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.c")
	if err := os.WriteFile(file, []byte("int p;\nint q;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cwe := "CWE-476"
	baseline := map[string]bool{
		computeFingerprint(cwe, file, "f", 1): true,
	}
	items := []planner.EvidenceItem{
		{Target: planner.TargetInfo{File: file, Function: "f", Line: 1}}, // already in baseline
		{Target: planner.TargetInfo{File: file, Function: "f", Line: 2}}, // new
	}
	kept, existing := filterByBaselineFingerprint(items, baseline, cwe)
	if existing != 1 {
		t.Errorf("expected 1 baseline-existing, got %d", existing)
	}
	if len(kept) != 1 || kept[0].Target.Line != 2 {
		t.Errorf("expected only line 2 kept, got %+v", kept)
	}
}

func TestComputeFingerprintStableAcrossLineDrift(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.c")

	// v1: statement at line 2.
	if err := os.WriteFile(file, []byte("int x;\np[0] = 1;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fp1 := computeFingerprint("CWE-476", file, "f", 2)

	// v2: an insertion above moves the SAME statement to line 3.
	if err := os.WriteFile(file, []byte("int x;\nint y;\np[0] = 1;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fp2 := computeFingerprint("CWE-476", file, "f", 3)

	if fp1 != fp2 {
		t.Errorf("fingerprint should survive line drift: %q != %q", fp1, fp2)
	}
}

func TestComputeFingerprintChangesWhenStatementChanges(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.c")
	if err := os.WriteFile(file, []byte("p[0] = 1;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fp1 := computeFingerprint("CWE-476", file, "f", 1)
	if err := os.WriteFile(file, []byte("p[0] = 2;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fp2 := computeFingerprint("CWE-476", file, "f", 1)
	if fp1 == fp2 {
		t.Error("fingerprint should change when the sink statement changes")
	}
}
