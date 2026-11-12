package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

func writeTestCFile(t *testing.T, dir string) string {
	t.Helper()
	cPath := filepath.Join(dir, "test.c")
	content := `#include <stdlib.h>
int *get_ptr(int x) {
    if (x < 0) return NULL;
    return (int*)malloc(sizeof(int));
}
int test_fn(int x) {
    int *p = get_ptr(x);
    return *p;
}
`
	if err := os.WriteFile(cPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return cPath
}

func runScan(t *testing.T, ctx context.Context, dbPath, outputDir, targetPath string) int {
	t.Helper()
	args := []string{"--db", dbPath, "--output-dir", outputDir, targetPath}
	return runScanCmd(ctx, args)
}

func TestScanRetention_PriorScanDirsPreserved(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir1 := filepath.Join(scansRoot, "sc_2026-08-11_140000_aaaaaa")
	scanDir2 := filepath.Join(scansRoot, "sc_2026-08-11_140001_bbbbbb")
	os.MkdirAll(scanDir1, 0755)
	os.MkdirAll(scanDir2, 0755)

	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	if code := runScan(t, ctx, dbPath, scanDir1, cPath); code != 0 {
		t.Fatalf("first scan failed with code %d", code)
	}

	sarif1, err := os.ReadFile(filepath.Join(scanDir1, "candidates.sarif"))
	if err != nil {
		t.Fatalf("scan1 sarif not found: %v", err)
	}
	report1, err := os.ReadFile(filepath.Join(scanDir1, "report.md"))
	if err != nil {
		t.Fatalf("scan1 report not found: %v", err)
	}

	if code := runScan(t, ctx, dbPath, scanDir2, cPath); code != 0 {
		t.Fatalf("second scan failed with code %d", code)
	}

	sarif1After, err := os.ReadFile(filepath.Join(scanDir1, "candidates.sarif"))
	if err != nil {
		t.Fatalf("scan1 sarif not found after scan2: %v", err)
	}
	report1After, err := os.ReadFile(filepath.Join(scanDir1, "report.md"))
	if err != nil {
		t.Fatalf("scan1 report not found after scan2: %v", err)
	}

	if string(sarif1) != string(sarif1After) {
		t.Error("scan1 candidates.sarif was modified by scan2")
	}
	if string(report1) != string(report1After) {
		t.Error("scan1 report.md was modified by scan2")
	}

	if _, err := os.Stat(filepath.Join(scanDir2, "candidates.sarif")); err != nil {
		t.Errorf("scan2 sarif not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(scanDir2, "report.md")); err != nil {
		t.Errorf("scan2 report not found: %v", err)
	}
}

func TestScanRetention_LatestSymlinkUpdated(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir1 := filepath.Join(scansRoot, "sc_2026-08-11_140000_cccccc")
	scanDir2 := filepath.Join(scansRoot, "sc_2026-08-11_140001_dddddd")
	os.MkdirAll(scanDir1, 0755)
	os.MkdirAll(scanDir2, 0755)

	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	runScan(t, ctx, dbPath, scanDir1, cPath)

	latestPath := filepath.Join(scansRoot, "latest")
	target1, err := os.Readlink(latestPath)
	if err != nil {
		t.Fatalf("latest symlink not found after scan1: %v", err)
	}
	if target1 != filepath.Base(scanDir1) {
		t.Errorf("expected latest -> %q, got %q", filepath.Base(scanDir1), target1)
	}

	runScan(t, ctx, dbPath, scanDir2, cPath)

	target2, err := os.Readlink(latestPath)
	if err != nil {
		t.Fatalf("latest symlink not found after scan2: %v", err)
	}
	if target2 != filepath.Base(scanDir2) {
		t.Errorf("expected latest -> %q, got %q", filepath.Base(scanDir2), target2)
	}
}

func TestScanRetention_ScanLogPersisted(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir := filepath.Join(scansRoot, "sc_2026-08-11_140000_eeeeee")
	os.MkdirAll(scanDir, 0755)

	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	if code := runScan(t, ctx, dbPath, scanDir, cPath); code != 0 {
		t.Fatalf("scan failed with code %d", code)
	}

	logPath := filepath.Join(scanDir, "scan.log")
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("scan.log not found: %v", err)
	}
	if len(content) == 0 {
		t.Error("scan.log is empty")
	}

	lines := splitLines(string(content))
	for i, line := range lines {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("scan.log line %d is not valid JSON: %v\nline: %s", i+1, err, line)
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	current := ""
	for _, ch := range s {
		if ch == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func TestScanZeroCandidateTypesMarkedDone(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir := filepath.Join(scansRoot, "sc_2026-08-11_140000_ffffff")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	if code := runScan(t, ctx, dbPath, scanDir, cPath); code != 0 {
		t.Fatalf("scan failed with code %d", code)
	}

	store, err := openStore(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	stats, err := store.ListScanStats(ctx, filepath.Base(scanDir))
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	for _, st := range stats {
		if st.FinalCount == 0 {
			zero++
			if st.AIStageStatus != "done" {
				t.Errorf("zero-candidate type %q ai_stage_status=%q, want done", st.VulnType, st.AIStageStatus)
			}
		}
	}
	if zero == 0 {
		t.Fatalf("expected some zero-candidate types, got none")
	}
}

func captureOutput(fn func() int) (stdout, stderr string, exitCode int) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	doneOut := make(chan struct{})
	doneErr := make(chan struct{})
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, rOut)
		stdout = buf.String()
		close(doneOut)
	}()

	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, rErr)
		stderr = buf.String()
		close(doneErr)
	}()

	exitCode = fn()

	wOut.Close()
	wErr.Close()
	<-doneOut
	<-doneErr
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	return
}

// TestScanCmd_ExplicitDBRelocatesScansRoot pins issue #264 #14: with an
// explicit --db and no --output-dir, the scan artifacts land under the scans
// root derived from the DB path (the DB directory's parent + scans), not
// under the launching cwd's .codeagent — the database and its artifacts
// stay in one tree.
func TestScanCmd_ExplicitDBRelocatesScansRoot(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	dbTree := t.TempDir()
	dbPath := filepath.Join(dbTree, "sgre.db")
	scansRoot := filepath.Join(filepath.Dir(dbTree), "scans")

	stdout, _, code := captureOutput(func() int {
		return runScanCmd(ctx, []string{"--db", dbPath, cPath})
	})
	if code != 0 {
		t.Fatalf("scan failed with code %d: %s", code, stdout)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("scan output is not JSON: %v\n%s", err, stdout)
	}
	scanDir, _ := out["scan_dir"].(string)
	if scanDir == "" {
		t.Fatal("scan output missing scan_dir")
	}
	if filepath.Dir(scanDir) != scansRoot {
		t.Errorf("scan_dir = %q, want under %q (the scans root derived from the DB path)", scanDir, scansRoot)
	}
	if _, err := os.Stat(filepath.Join(scanDir, "candidates.sarif")); err != nil {
		t.Errorf("scan artifacts missing under the relocated root: %v", err)
	}
}

func TestScanCmd_JSONEnvelopeHasTargetPathAndScanDir(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir := filepath.Join(scansRoot, "sc_2026-08-11_150000_xxxxxx")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	stdout, _, exitCode := captureOutput(func() int {
		return runScan(t, ctx, dbPath, scanDir, cPath)
	})
	if exitCode != 0 {
		t.Fatalf("scan failed with code %d", exitCode)
	}

	var result map[string]interface{}

	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}

	targetPath, ok := result["target_path"].(string)
	if !ok || targetPath == "" {
		t.Error("JSON envelope missing target_path field")
	}
	scanDirField, ok := result["scan_dir"].(string)
	if !ok || scanDirField == "" {
		t.Error("JSON envelope missing scan_dir field")
	}

	for _, key := range []string{"scan_id", "candidates_by_type", "auto_confirmed_by_type", "seeds_by_type", "total_candidates", "files_with_candidates_count", "index_summary", "existing_findings_count"} {
		if _, ok := result[key]; !ok {
			t.Errorf("JSON envelope missing existing key: %s", key)
		}
	}
}

func TestScanCmd_StderrHasSummaryTable(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir := filepath.Join(scansRoot, "sc_2026-08-11_150001_yyyyyy")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	_, stderr, exitCode := captureOutput(func() int {
		return runScan(t, ctx, dbPath, scanDir, cPath)
	})
	if exitCode != 0 {
		t.Fatalf("scan failed with code %d", exitCode)
	}

	if !bytes.Contains([]byte(stderr), []byte("## SecGuard Scan Summary")) {
		t.Error("stderr does not contain summary table header")
	}
	if !bytes.Contains([]byte(stderr), []byte("| Field | Value |")) {
		t.Error("stderr does not contain summary table format")
	}
}

func TestScanCmd_StdoutIsValidJSON(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir := filepath.Join(scansRoot, "sc_2026-08-11_150002_zzzzzz")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	stdout, _, exitCode := captureOutput(func() int {
		return runScan(t, ctx, dbPath, scanDir, cPath)
	})
	if exitCode != 0 {
		t.Fatalf("scan failed with code %d", exitCode)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Errorf("stdout is not valid JSON: %v", err)
	}
}

func TestScanCmd_JSONEnvelopeHasSummaryField(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir := filepath.Join(scansRoot, "sc_2026-08-11_150003_ffffff")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	stdout, _, exitCode := captureOutput(func() int {
		return runScan(t, ctx, dbPath, scanDir, cPath)
	})
	if exitCode != 0 {
		t.Fatalf("scan failed with code %d", exitCode)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}

	summary, ok := result["_summary"].(string)
	if !ok {
		t.Fatal("JSON envelope missing _summary field or not a string")
	}
	if !bytes.Contains([]byte(summary), []byte("## SecGuard Scan Summary")) {
		t.Error("_summary field does not contain summary table header")
	}
	if !bytes.Contains([]byte(summary), []byte("| Field | Value |")) {
		t.Error("_summary field does not contain summary table format")
	}
}

func TestScanOutput_CodeagentAtProjectRoot(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	srcDir := filepath.Join(root, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestCFile(t, srcDir)

	// Run the scan from the project root (cwd), targeting the src subdir, using
	// the DEFAULT db/output resolution (no --db, no --output-dir).
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	if code := runScanCmd(ctx, []string{"src"}); code != 0 {
		t.Fatalf("scan failed with code %d", code)
	}

	// .codeagent must be at the project root, never under the scan target.
	if _, err := os.Stat(filepath.Join(root, ".codeagent")); err != nil {
		t.Fatalf(".codeagent missing at project root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(srcDir, ".codeagent")); err == nil {
		t.Fatal(".codeagent leaked into scan target src/ — should be at project root")
	}
}

// TestScanCmd_SkipDetectorsEnvelope verifies the detector switch reaches the
// scan envelope: the applied names are echoed (sorted) and a kebab-case
// spelling is normalized to its snake_case detector name (issue #253 P0-3:
// `secguard types` prints kebab-case vuln types, so users naturally pass
// kebab names to --skip-detectors).
func TestScanCmd_SkipDetectorsEnvelope(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir := filepath.Join(scansRoot, "sc_2026-08-11", "sc_2026-08-11_150001_yyyyyy")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	config.SetSkipDetectorsOverride("memory-leak, unchecked_return")
	defer config.SetSkipDetectorsOverride("")

	stdout, _, exitCode := captureOutput(func() int {
		return runScanCmd(ctx, []string{"--db", dbPath, "--output-dir", scanDir, "--skip-detectors", "memory-leak, unchecked_return", cPath})
	})
	if exitCode != 0 {
		t.Fatalf("scan failed with code %d", exitCode)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	got, ok := result["detectors_skipped"].([]interface{})
	if !ok {
		t.Fatalf("detectors_skipped missing or not a list: %#v", result["detectors_skipped"])
	}
	want := []string{"memory_leak", "unchecked_return"}
	if len(got) != len(want) {
		t.Fatalf("detectors_skipped = %v, want %v", got, want)
	}
	for i, name := range want {
		if got[i] != name {
			t.Fatalf("detectors_skipped = %v, want %v (sorted, kebab normalized to snake)", got, want)
		}
	}
}

// TestScanCmd_SkipDetectorsUnknownHardFails pins the issue #253 P0-3 contract:
// an unknown detector name must abort the scan with a non-zero exit code and
// list the legal names. Warn-and-continue left the user believing a crashing
// detector was off while it ran again.
func TestScanCmd_SkipDetectorsUnknownHardFails(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scanDir := filepath.Join(root, ".codeagent", "secguard-clang", "scans", "sc_2026-08-11", "sc_2026-08-11_150001_zzzzzz")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	config.SetSkipDetectorsOverride("memory_leak, not_a_detector")
	defer config.SetSkipDetectorsOverride("")

	stdout, _, exitCode := captureOutput(func() int {
		return runScanCmd(ctx, []string{"--db", dbPath, "--output-dir", scanDir, "--skip-detectors", "memory_leak, not_a_detector", cPath})
	})
	if exitCode == 0 {
		t.Fatalf("an unknown skip-detectors name must fail the scan, got exit 0: %s", stdout)
	}
	if !strings.Contains(stdout, "not_a_detector") || !strings.Contains(stdout, "integer_overflow") {
		t.Fatalf("the error must name the unknown detector and list the registered ones: %s", stdout)
	}
	// A normal error return must leave the same visible failure marker as a
	// panic/OOM (issue #253 P0-4); previously only the stale sweep wrote one.
	if _, err := os.Stat(filepath.Join(scanDir, ".failed")); err != nil {
		t.Errorf("a failed scan must leave a .failed marker in its scan dir: %v", err)
	}
}
