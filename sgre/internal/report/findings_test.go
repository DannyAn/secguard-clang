package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// writeCandidate lays down a candidate evidence file exactly as writeCandidates
// produces it, so the verdict writer is exercised against the real input shape.
func writeCandidate(t *testing.T, scanDir, vulnType, name string) string {
	t.Helper()
	dir := filepath.Join(scanDir, CandidatesDir, vulnType)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "# Null Deref in f\n\n**CWE:** CWE-476\n\n" +
		"> Pipeline **candidate evidence** — not a defect and not a verdict.\n" +
		"> Classified findings live in `" + FindingsDir + "/" + vulnType + "/`.\n\n" +
		"## Location\n\n- **File:** `/repo/src/a.c:13`\n- **Function:** `f`\n\n" +
		"## Evidence\n\n- **source:** p assigned a possibly-null value\n\n" +
		"## Pipeline Assessment\n\n- **Suspicion Level (pipeline prior, not a verdict):** confirmed\n" +
		"- **AI Verdict:** _unclassified_\n\n" +
		"## Fix Suggestion\n\nAdd a NULL check.\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func confirmedUpdate() PerFindingUpdate {
	return PerFindingUpdate{
		Summary:        "malloc 未判空即解引用",
		Reasoning:      "分配后立即解引用",
		ExceptionCheck: "无 safe wrapper",
		FixStrategy:    "if (p == NULL) return -1;",
		Status:         "confirmed",
		Severity:       "high",
		Confidence:     0.9,
		FunctionName:   "f",
	}
}

func lsFindings(t *testing.T, scanDir, vulnType string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(scanDir, FindingsDir, vulnType))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSyncPerFinding_ConfirmedGetsSuffixedFile(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")

	res, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, confirmedUpdate())
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != PerFindingWritten {
		t.Fatalf("action = %q, want %q", res.Action, PerFindingWritten)
	}
	if got := filepath.Base(res.Path); got != "001_src_a_c_13_confirmed.md" {
		t.Fatalf("finding file = %q, want 001_src_a_c_13_confirmed.md", got)
	}
	data, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "- **Status:** confirmed (severity: high, confidence: 90%)") {
		t.Errorf("verdict line missing:\n%s", content)
	}
	if strings.Contains(content, "Suspicion Level") {
		t.Errorf("pipeline prior must not leak into the verdict file:\n%s", content)
	}
	if strings.Contains(content, "_pending_") {
		t.Errorf("verdict file must never say pending:\n%s", content)
	}
	// Pipeline evidence and the AI's structured justification both survive.
	for _, want := range []string{"p assigned a possibly-null value", "## Summary", "## Reasoning", "## Exception Check", "## Fix Strategy"} {
		if !strings.Contains(content, want) {
			t.Errorf("missing %q:\n%s", want, content)
		}
	}
	// The candidate file records where the verdict went.
	cand, err := os.ReadFile(filepath.Join(dir, CandidatesDir, "null-deref", "001_src_a_c_13.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cand), "- **AI Verdict:** confirmed — see `findings/null-deref/001_src_a_c_13_confirmed.md`") {
		t.Errorf("candidate should point at its verdict file:\n%s", cand)
	}
}

// A finding written twice (write, then A5 review) must not duplicate sections.
func TestSyncPerFinding_Idempotent(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")

	for i := 0; i < 2; i++ {
		if _, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, confirmedUpdate()); err != nil {
			t.Fatal(err)
		}
	}
	names := lsFindings(t, dir, "null-deref")
	if len(names) != 1 {
		t.Fatalf("findings dir = %v, want exactly one file", names)
	}
	data, err := os.ReadFile(filepath.Join(dir, FindingsDir, "null-deref", names[0]))
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"## Summary", "## Reasoning", "## Exception Check", "## Fix Strategy"} {
		if n := strings.Count(string(data), section); n != 1 {
			t.Errorf("%q appears %d times, want 1\n%s", section, n, data)
		}
	}
}

// The reported production bug: dismissed candidates were still written to
// findings/<vuln-type>/, so a "已排除误报" console note did not match the disk.
func TestSyncPerFinding_DismissedNeverEntersFindings(t *testing.T) {
	dir := t.TempDir()
	candPath := writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")

	u := PerFindingUpdate{
		Status: "dismissed", FunctionName: "f",
		Reasoning: "所有 confirmed 条目在解引用前都有 NULL 检查",
	}
	res, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, u)
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != "" {
		t.Errorf("dismissed verdict must produce no findings file, got %q", res.Path)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 0 {
		t.Errorf("findings dir should be empty, got %v", names)
	}
	data, err := os.ReadFile(candPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "- **AI Verdict:** dismissed") {
		t.Errorf("dismissal should be recorded on the candidate file:\n%s", content)
	}
	if !strings.Contains(content, "所有 confirmed 条目在解引用前都有 NULL 检查") {
		t.Errorf("dismissal reason should be kept for audit:\n%s", content)
	}
}

// A5 review transitions: suspected → confirmed renames, confirmed → dismissed
// deletes. Both must leave exactly one (or zero) file per location.
func TestSyncPerFinding_VerdictTransitions(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")

	suspected := confirmedUpdate()
	suspected.Status = "suspected"
	if _, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, suspected); err != nil {
		t.Fatal(err)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 1 || names[0] != "001_src_a_c_13_suspected.md" {
		t.Fatalf("after suspected: %v", names)
	}

	if _, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, confirmedUpdate()); err != nil {
		t.Fatal(err)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 1 || names[0] != "001_src_a_c_13_confirmed.md" {
		t.Fatalf("after promote to confirmed: %v", names)
	}

	dismissed := confirmedUpdate()
	dismissed.Status = "dismissed"
	res, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, dismissed)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != PerFindingRemoved {
		t.Errorf("action = %q, want %q", res.Action, PerFindingRemoved)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 0 {
		t.Fatalf("after dismissal: %v", names)
	}
}

// A verdict written without any candidate evidence file (a direct
// `report --write`) must still produce a properly suffixed finding file.
func TestSyncPerFinding_NoCandidateStillWrites(t *testing.T) {
	dir := t.TempDir()
	u := confirmedUpdate()
	u.Evidence = "- **sink:** memcpy without bound check"

	res, err := SyncPerFinding(dir, "buffer-overflow", "src/b.c", 7, u)
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(res.Path); got != "001_src_b_c_7_confirmed.md" {
		t.Fatalf("finding file = %q", got)
	}
	data, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "memcpy without bound check") {
		t.Errorf("DB evidence should be used when no candidate file exists:\n%s", data)
	}
}

// A status the pipeline does not recognize must not touch findings/ at all.
func TestSyncPerFinding_UnknownStatusLeavesDirAlone(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")
	if _, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, confirmedUpdate()); err != nil {
		t.Fatal(err)
	}
	open := confirmedUpdate()
	open.Status = "open"
	res, err := SyncPerFinding(dir, "null-deref", "src/a.c", 13, open)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != PerFindingNone || res.Verdict != "" {
		t.Errorf("open status should be a no-op, got %+v", res)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 1 {
		t.Errorf("existing verdict file should survive, got %v", names)
	}
}

func TestReconcileFindings_SweepsUnclassifiedAndDismissed(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")
	writeCandidate(t, dir, "null-deref", "002_src_a_c_20.md")

	// Simulate the broken 0.3.5 state: candidate-stage files sitting directly
	// in findings/ with no verdict suffix, plus a stale dismissed file.
	stale := filepath.Join(dir, FindingsDir, "null-deref")
	if err := os.MkdirAll(stale, 0755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"001_src_a_c_13.md", "002_src_a_c_20.md", "003_src_a_c_31_dismissed.md"} {
		if err := os.WriteFile(filepath.Join(stale, n), []byte("# stale\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	findings := []*db.Finding{
		{RuleID: "CWE-476", FilePath: "src/a.c", LineNumber: 13, FunctionName: "f",
			Status: "confirmed", Severity: "high", Confidence: 0.9, Summary: "real"},
		{RuleID: "CWE-476", FilePath: "src/a.c", LineNumber: 20, FunctionName: "f",
			Status: "dismissed", Reasoning: "guarded"},
		{RuleID: "CWE-476", FilePath: "src/a.c", LineNumber: 31, FunctionName: "f",
			Status: "dismissed", Reasoning: "safe wrapper"},
	}
	res, err := ReconcileFindings(dir, findings)
	if err != nil {
		t.Fatal(err)
	}
	if res.Written != 1 {
		t.Errorf("written = %d, want 1", res.Written)
	}
	names := lsFindings(t, dir, "null-deref")
	if len(names) != 1 || names[0] != "001_src_a_c_13_confirmed.md" {
		t.Fatalf("findings dir = %v, want only the confirmed finding", names)
	}
}

// The A5 review verdict (review_status) wins over the first-pass status, so a
// reviewed-away finding disappears from the review surface. ReconcileFindings
// keys on the FINAL verdict: suspected-kept survives as suspected, while a
// never-reviewed suspected (ReviewStatus empty) is an incomplete verdict and is
// swept out.
func TestReconcileFindings_UsesFinalStatus(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")

	f := &db.Finding{RuleID: "CWE-476", FilePath: "src/a.c", LineNumber: 13, FunctionName: "f",
		Status: "suspected", ReviewStatus: "suspected-kept", Severity: "medium", Confidence: 0.5}
	if _, err := ReconcileFindings(dir, []*db.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 1 || names[0] != "001_src_a_c_13_suspected.md" {
		t.Fatalf("suspected-kept should survive as suspected: %v", names)
	}

	f.ReviewStatus = "dismissed"
	res, err := ReconcileFindings(dir, []*db.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed == 0 {
		t.Errorf("removed = %d, want > 0", res.Removed)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 0 {
		t.Fatalf("after A5 dismissal: %v", names)
	}
}

// A plain suspected finding (no review_status) is a final first-pass verdict —
// A5 has been folded into A4 — so it produces a findings/ file like any other
// actionable verdict.
func TestReconcileFindings_IncludesPlainSuspected(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")

	f := &db.Finding{RuleID: "CWE-476", FilePath: "src/a.c", LineNumber: 13, FunctionName: "f",
		Status: "suspected", ReviewStatus: "", Severity: "medium", Confidence: 0.5}
	res, err := ReconcileFindings(dir, []*db.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	if res.Written != 1 {
		t.Errorf("written = %d, want 1 (plain suspected is final)", res.Written)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 1 || names[0] != "001_src_a_c_13_suspected.md" {
		t.Fatalf("plain suspected must survive as suspected: %v", names)
	}
}

func TestLatestScanID(t *testing.T) {
	root := t.TempDir()
	scansDir := filepath.Join(root, CodeagentDir, ProductDir, ScansDir)
	scanID := "sc_2026-08-21_121958_584d9f"
	if err := os.MkdirAll(filepath.Join(scansDir, scanID), 0755); err != nil {
		t.Fatal(err)
	}
	if LatestScanID(root) != "" {
		t.Errorf("no latest pointer yet, want empty")
	}
	if err := UpdateLatest(scansDir, scanID); err != nil {
		t.Fatal(err)
	}
	if got := LatestScanID(root); got != scanID {
		t.Errorf("LatestScanID = %q, want %q", got, scanID)
	}
}

// A reviewer must be able to judge a finding without opening an editor.
func TestSyncPerFinding_EmbedsCodeContext(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.c")
	var lines []string
	for i := 1; i <= 40; i++ {
		lines = append(lines, "int line"+strconv.Itoa(i)+" = "+strconv.Itoa(i)+";")
	}
	if err := os.WriteFile(src, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	candDir := filepath.Join(dir, CandidatesDir, "null-deref")
	if err := os.MkdirAll(candDir, 0755); err != nil {
		t.Fatal(err)
	}
	cand := "# Null Deref in f\n\n**CWE:** CWE-476\n\n## Location\n\n- **File:** `" + src + ":20`\n- **Function:** `f`\n\n" +
		"## Evidence\n\n- **source:** p may be null\n\n## Pipeline Assessment\n\n- **AI Verdict:** _unclassified_\n\n## Fix Suggestion\n\nCheck.\n"
	if err := os.WriteFile(filepath.Join(candDir, "001_a_c_20.md"), []byte(cand), 0644); err != nil {
		t.Fatal(err)
	}

	u := confirmedUpdate()
	u.ContextLines = 5
	res, err := SyncPerFinding(dir, "null-deref", src, 20, u)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "## Code Context") {
		t.Fatalf("verdict file should carry a code context section:\n%s", content)
	}
	if !strings.Contains(content, "> 20 | int line20 = 20;") {
		t.Errorf("the finding line should be marked:\n%s", content)
	}
	for _, want := range []string{"  15 | int line15", "  25 | int line25"} {
		if !strings.Contains(content, want) {
			t.Errorf("context window should include %q:\n%s", want, content)
		}
	}
	if strings.Contains(content, "line14 ") || strings.Contains(content, "  26 |") {
		t.Errorf("context window should stop at ±5 lines:\n%s", content)
	}
}

// Source embedding must be switchable off for repositories that cannot have
// source copied into report artifacts, and must degrade quietly when the file
// is not on disk.
func TestSyncPerFinding_CodeContextOptionalAndSafe(t *testing.T) {
	dir := t.TempDir()

	u := confirmedUpdate()
	u.ContextLines = -1 // disabled
	res, err := SyncPerFinding(dir, "null-deref", "src/missing.c", 13, u)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(res.Path)
	if strings.Contains(string(data), "## Code Context") {
		t.Errorf("ContextLines<0 must disable source embedding:\n%s", data)
	}

	u2 := confirmedUpdate()
	u2.ContextLines = 10
	res2, err := SyncPerFinding(dir, "null-deref", "src/does_not_exist.c", 99, u2)
	if err != nil {
		t.Fatalf("a missing source file must not fail the write: %v", err)
	}
	data2, _ := os.ReadFile(res2.Path)
	if strings.Contains(string(data2), "## Code Context") {
		t.Errorf("unreadable source should simply omit the section:\n%s", data2)
	}
}

// findings/ is a projection of the CURRENT verdict, so a corrected verdict for
// the same location must win regardless of row order.
func TestReconcileFindings_LatestVerdictWins(t *testing.T) {
	dir := t.TempDir()
	writeCandidate(t, dir, "null-deref", "001_src_a_c_13.md")

	findings := []*db.Finding{
		{ID: 1, RuleID: "CWE-476", FilePath: "src/a.c", LineNumber: 13, FunctionName: "f", Status: "confirmed", Severity: "high"},
		{ID: 2, RuleID: "CWE-476", FilePath: "src/a.c", LineNumber: 13, FunctionName: "f", Status: "dismissed", Reasoning: "guarded after all"},
	}
	if _, err := ReconcileFindings(dir, findings); err != nil {
		t.Fatal(err)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 0 {
		t.Fatalf("latest verdict (dismissed) should win, got %v", names)
	}

	// Reversed input order must produce the same disk state.
	findings[0], findings[1] = findings[1], findings[0]
	if _, err := ReconcileFindings(dir, findings); err != nil {
		t.Fatal(err)
	}
	if names := lsFindings(t, dir, "null-deref"); len(names) != 0 {
		t.Fatalf("verdict projection must not depend on row order, got %v", names)
	}
}

// A re-scan into the same directory must not leave a previous run's candidate
// or verdict files behind.
func TestScanOutputWrite_ResetsDerivedTrees(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{
		ScanDir:    dir,
		ScanID:     "sc_test",
		ReportPath: filepath.Join(dir, ReportFile),
		SarifPath:  filepath.Join(dir, SarifFile),
	}
	ghostCand := filepath.Join(dir, CandidatesDir, "double-free", "009_gone_c_1.md")
	ghostFinding := filepath.Join(dir, FindingsDir, "double-free", "009_gone_c_1_confirmed.md")
	for _, p := range []string{ghostCand, ghostFinding} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("# stale run\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := o.Write(candidatePackages(), IndexSummary{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{ghostCand, ghostFinding} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stale file %s survived a re-scan (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, CandidatesDir, "null-deref", "001_src_a_c_13.md")); err != nil {
		t.Errorf("current candidates should be written: %v", err)
	}
}
