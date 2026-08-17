package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
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

	scansRoot := filepath.Join(root, ".codeagent", "zhuque-secguard", "scans")
	scanDir1 := filepath.Join(scansRoot, "2026-08-11_140000_aaaa")
	scanDir2 := filepath.Join(scansRoot, "2026-08-11_140001_bbbb")
	os.MkdirAll(scanDir1, 0755)
	os.MkdirAll(scanDir2, 0755)

	dbPath := filepath.Join(root, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	if code := runScan(t, ctx, dbPath, scanDir1, cPath); code != 0 {
		t.Fatalf("first scan failed with code %d", code)
	}

	sarif1, err := os.ReadFile(filepath.Join(scanDir1, "sarif.sarif"))
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

	sarif1After, err := os.ReadFile(filepath.Join(scanDir1, "sarif.sarif"))
	if err != nil {
		t.Fatalf("scan1 sarif not found after scan2: %v", err)
	}
	report1After, err := os.ReadFile(filepath.Join(scanDir1, "report.md"))
	if err != nil {
		t.Fatalf("scan1 report not found after scan2: %v", err)
	}

	if string(sarif1) != string(sarif1After) {
		t.Error("scan1 sarif.sarif was modified by scan2")
	}
	if string(report1) != string(report1After) {
		t.Error("scan1 report.md was modified by scan2")
	}

	if _, err := os.Stat(filepath.Join(scanDir2, "sarif.sarif")); err != nil {
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

	scansRoot := filepath.Join(root, ".codeagent", "zhuque-secguard", "scans")
	scanDir1 := filepath.Join(scansRoot, "2026-08-11_140000_cccc")
	scanDir2 := filepath.Join(scansRoot, "2026-08-11_140001_dddd")
	os.MkdirAll(scanDir1, 0755)
	os.MkdirAll(scanDir2, 0755)

	dbPath := filepath.Join(root, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
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

	scansRoot := filepath.Join(root, ".codeagent", "zhuque-secguard", "scans")
	scanDir := filepath.Join(scansRoot, "2026-08-11_140000_eeee")
	os.MkdirAll(scanDir, 0755)

	dbPath := filepath.Join(root, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
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

func TestScanCmd_JSONEnvelopeHasTargetPathAndScanDir(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "zhuque-secguard", "scans")
	scanDir := filepath.Join(scansRoot, "2026-08-11_150000_xxxx")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
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

	for _, key := range []string{"scan_id", "candidates_by_type", "total_candidates", "files_with_candidates", "index_summary", "existing_findings"} {
		if _, ok := result[key]; !ok {
			t.Errorf("JSON envelope missing existing key: %s", key)
		}
	}
}

func TestScanCmd_StderrHasSummaryTable(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)

	scansRoot := filepath.Join(root, ".codeagent", "zhuque-secguard", "scans")
	scanDir := filepath.Join(scansRoot, "2026-08-11_150001_yyyy")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
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

	scansRoot := filepath.Join(root, ".codeagent", "zhuque-secguard", "scans")
	scanDir := filepath.Join(scansRoot, "2026-08-11_150002_zzzz")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
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

	scansRoot := filepath.Join(root, ".codeagent", "zhuque-secguard", "scans")
	scanDir := filepath.Join(scansRoot, "2026-08-11_150003_ffff")
	os.MkdirAll(scanDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
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
