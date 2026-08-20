package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTruncateAtFirstSection(t *testing.T) {
	in := "## Location\n\nx.c:13\n\n## Classification\n\n- **Status:** confirmed\n\n## Summary\n\nold\n\n## Fix Strategy\n\nold fix\n"
	got := truncateAtFirstSection(in)
	if strings.Contains(got, "## Summary") || strings.Contains(got, "## Fix Strategy") || strings.Contains(got, "old") {
		t.Errorf("truncateAtFirstSection should strip Summary/Fix, got:\n%s", got)
	}
	if !strings.Contains(got, "## Classification") {
		t.Errorf("truncateAtFirstSection should keep Location/Classification, got:\n%s", got)
	}
}

func TestRemoveLineByPrefix(t *testing.T) {
	in := "- **Suspicion Level:** suspected\n- **Status:** confirmed\n"
	got := removeLineByPrefix(in, "- **Suspicion Level:** ")
	if strings.Contains(got, "Suspicion Level") {
		t.Errorf("Suspicion Level line should be removed, got:\n%s", got)
	}
	if !strings.Contains(got, "- **Status:**") {
		t.Errorf("Status line should remain, got:\n%s", got)
	}
}

func TestRewritePerFinding_Idempotent(t *testing.T) {
	dir := t.TempDir()
	vulnDir := filepath.Join(dir, "unchecked-return")
	if err := os.MkdirAll(vulnDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Candidate-stage file, as writePerFinding produces it.
	candidate := `# Unchecked Return in f

**CWE:** CWE-252

## Location

- **File:** ` + "`src/a.c:13`" + `
- **Function:** ` + "`f`" + `

## Evidence

- **sink:** return value of malloc is not checked in function f at line 13

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting AI classification)

## Fix Suggestion

Add a NULL check.
`
	path := filepath.Join(vulnDir, "001_src_a_c_13.md")
	if err := os.WriteFile(path, []byte(candidate), 0644); err != nil {
		t.Fatal(err)
	}

	update := PerFindingUpdate{
		Summary:        "malloc 未判空即解引用",
		Reasoning:      "分配后立即解引用",
		ExceptionCheck: "无 safe wrapper",
		FixStrategy:    "if (p == NULL) return -1;",
		Status:         "confirmed",
		Severity:       "high",
		Confidence:     0.9,
		FunctionName:   "f",
	}

	if _, err := RewritePerFinding(dir, "unchecked-return", "src/a.c", 13, update); err != nil {
		t.Fatal(err)
	}
	// Second pass (as a --review after --write would) must not duplicate.
	if _, err := RewritePerFinding(dir, "unchecked-return", "src/a.c", 13, update); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(vulnDir, "001_src_a_c_13_confirmed.md"))
	if err != nil {
		t.Fatalf("read rewritten file: %v", err)
	}
	content := string(data)

	for _, dup := range []string{"## Summary", "## Reasoning", "## Exception Check", "## Fix Strategy"} {
		if n := strings.Count(content, dup); n != 1 {
			t.Errorf("%q appears %d times, want exactly 1\n%s", dup, n, content)
		}
	}
	if strings.Contains(content, "Suspicion Level") {
		t.Errorf("Suspicion Level (pipeline prior) should be removed, got:\n%s", content)
	}
	if strings.Contains(content, "Fix Suggestion") {
		t.Errorf("candidate-stage generic Fix Suggestion should be replaced, got:\n%s", content)
	}
	if !strings.Contains(content, "if (p == NULL) return -1;") {
		t.Errorf("Fix Strategy content missing:\n%s", content)
	}
}

func TestRewritePerFinding_ReviewPreservesContent(t *testing.T) {
	dir := t.TempDir()
	vulnDir := filepath.Join(dir, "unchecked-return")
	if err := os.MkdirAll(vulnDir, 0755); err != nil {
		t.Fatal(err)
	}
	candidate := "# Unchecked Return in f\n\n**CWE:** CWE-252\n\n## Location\n\n- **File:** `src/a.c:13`\n\n## Evidence\n\n- **sink:** malloc unchecked\n\n## Classification\n\n- **Suspicion Level:** suspected\n- **Status:** _pending_ (awaiting AI classification)\n\n## Fix Suggestion\n\nAdd a NULL check.\n"
	path := filepath.Join(vulnDir, "001_src_a_c_13.md")
	if err := os.WriteFile(path, []byte(candidate), 0644); err != nil {
		t.Fatal(err)
	}

	write := PerFindingUpdate{
		Summary: "malloc 未判空", Reasoning: "分配后立即解引用", FixStrategy: "if (p == NULL) return -1;",
		Status: "suspected", FunctionName: "f",
	}
	if _, err := RewritePerFinding(dir, "unchecked-return", "src/a.c", 13, write); err != nil {
		t.Fatal(err)
	}
	// The A5 review re-passes the persisted structured content (the CLI now
	// sends Summary/Reasoning/FixStrategy alongside the new verdict), so the
	// second pass must not wipe them.
	review := PerFindingUpdate{
		Status: "confirmed", Severity: "high", Confidence: 0.9, FunctionName: "f",
		Summary: "malloc 未判空", Reasoning: "分配后立即解引用", FixStrategy: "if (p == NULL) return -1;",
	}
	if _, err := RewritePerFinding(dir, "unchecked-return", "src/a.c", 13, review); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(vulnDir, "001_src_a_c_13_confirmed.md"))
	if err != nil {
		t.Fatalf("read rewritten file: %v", err)
	}
	content := string(data)
	for _, section := range []string{"## Summary", "## Reasoning", "## Fix Strategy"} {
		if n := strings.Count(content, section); n != 1 {
			t.Errorf("%q appears %d times after write+review, want exactly 1\n%s", section, n, content)
		}
	}
	if !strings.Contains(content, "malloc 未判空") {
		t.Errorf("review should preserve the Summary content:\n%s", content)
	}
	if !strings.Contains(content, "if (p == NULL) return -1;") {
		t.Errorf("review should preserve the Fix Strategy content:\n%s", content)
	}
}
