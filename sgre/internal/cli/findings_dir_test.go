//go:build !nosqlite

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/report"
)

const fixtureScanID = "sc_2026-01-01_000000_aaaaaa"

// findingsFixture lays out a project root with one scan directory holding a
// candidate evidence file, mirroring what `secguard scan` produces.
func findingsFixture(t *testing.T, vulnType, candidateName string) (root, dbPath, scanDir string) {
	t.Helper()
	ctx := context.Background()
	root = t.TempDir()
	dbPath = filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		t.Fatal(err)
	}
	scansDir := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	scanDir = filepath.Join(scansDir, fixtureScanID)
	candDir := filepath.Join(scanDir, report.CandidatesDir, vulnType)
	if err := os.MkdirAll(candDir, 0755); err != nil {
		t.Fatal(err)
	}
	candidate := "# Null Deref in f\n\n**CWE:** CWE-476\n\n" +
		"## Location\n\n- **File:** `" + root + "/src/a.c:13`\n- **Function:** `f`\n\n" +
		"## Evidence\n\n- **source:** p may be null\n\n" +
		"## Pipeline Assessment\n\n- **Suspicion Level (pipeline prior, not a verdict):** confirmed\n" +
		"- **AI Verdict:** _unclassified_\n\n## Fix Suggestion\n\nAdd a NULL check.\n"
	if err := os.WriteFile(filepath.Join(candDir, candidateName), []byte(candidate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := report.UpdateLatest(scansDir, fixtureScanID); err != nil {
		t.Fatal(err)
	}

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{
		ScanID: fixtureScanID, VulnType: vulnType, SeedCount: 1, FinalCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return root, dbPath, scanDir
}

func findingFiles(t *testing.T, scanDir, vulnType string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(scanDir, report.FindingsDir, vulnType))
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

func writeFinding(t *testing.T, dbPath, scanDir, status, line string, extra ...string) map[string]interface{} {
	t.Helper()
	args := []string{
		"--db", dbPath, "--write",
		"--rule-id", "CWE-476", "--severity", "high", "--confidence", "90",
		"--status", status, "--file", "src/a.c", "--line", line, "--function", "f",
		"--properties", `{"summary":"s","reasoning":"r","fix_strategy":"fix","exception_check":"e"}`,
	}
	if scanDir != "" {
		args = append(args, "--scan-id", fixtureScanID, "--output-dir", scanDir)
	}
	args = append(args, extra...)

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(context.Background(), args)
	})
	if exitCode != 0 {
		t.Fatalf("report --write failed (exit %d): %s", exitCode, stdout)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("write response is not JSON: %s", stdout)
	}
	return out
}

func TestReportWrite_ConfirmedGetsStatusSuffix(t *testing.T) {
	_, dbPath, scanDir := findingsFixture(t, "null-deref", "001_src_a_c_13.md")

	out := writeFinding(t, dbPath, scanDir, "confirmed", "13")
	if out["per_finding_action"] != "written" {
		t.Fatalf("per_finding_action = %v, want written (response: %v)", out["per_finding_action"], out)
	}
	names := findingFiles(t, scanDir, "null-deref")
	if len(names) != 1 || names[0] != "001_src_a_c_13_confirmed.md" {
		t.Fatalf("findings dir = %v, want [001_src_a_c_13_confirmed.md]", names)
	}
	if w, ok := out["per_finding_warning"]; ok {
		t.Errorf("unexpected warning: %v", w)
	}
}

// The production complaint: entries the AI excluded as false positives still
// showed up under findings/<vuln-type>/.
func TestReportWrite_DismissedStaysOutOfFindings(t *testing.T) {
	_, dbPath, scanDir := findingsFixture(t, "null-deref", "001_src_a_c_13.md")

	writeFinding(t, dbPath, scanDir, "confirmed", "13")
	out := writeFinding(t, dbPath, scanDir, "dismissed", "13")

	if out["per_finding_action"] != "removed" {
		t.Errorf("per_finding_action = %v, want removed", out["per_finding_action"])
	}
	if names := findingFiles(t, scanDir, "null-deref"); len(names) != 0 {
		t.Fatalf("findings dir = %v, want empty after dismissal", names)
	}
	cand, err := os.ReadFile(filepath.Join(scanDir, report.CandidatesDir, "null-deref", "001_src_a_c_13.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cand), "- **AI Verdict:** dismissed") {
		t.Errorf("candidate file should record the dismissal:\n%s", cand)
	}
}

// A write with no scan id used to silently skip the per-finding file entirely,
// which is how the status suffix "disappeared" in production. It now inherits
// the latest scan and, if even that is impossible, says so out loud.
func TestReportWrite_InheritsLatestScanID(t *testing.T) {
	root, dbPath, scanDir := findingsFixture(t, "null-deref", "001_src_a_c_13.md")
	t.Chdir(root)

	out := writeFinding(t, dbPath, "", "confirmed", "13")
	if out["scan_id_source"] != "latest" {
		t.Errorf("scan_id_source = %v, want latest", out["scan_id_source"])
	}
	if out["scan_id"] != fixtureScanID {
		t.Errorf("scan_id = %v, want %s", out["scan_id"], fixtureScanID)
	}
	if names := findingFiles(t, scanDir, "null-deref"); len(names) != 1 {
		t.Fatalf("findings dir = %v, want the verdict file", names)
	}
}

func TestReportWrite_WarnsWhenNoScanDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	dbPath := filepath.Join(root, "test.db")

	out := writeFinding(t, dbPath, "", "confirmed", "13")
	if out["per_finding_action"] != "skipped" {
		t.Errorf("per_finding_action = %v, want skipped", out["per_finding_action"])
	}
	w, ok := out["per_finding_warning"].(string)
	if !ok || !strings.Contains(w, "--scan-id") {
		t.Errorf("expected an actionable warning, got %v", out["per_finding_warning"])
	}
}

// The audit stage is the backstop: whatever the classification pass did or
// failed to do, findings/ must end up equal to the DB's actionable verdicts.
func TestReportAudit_ReconcilesFindingsDir(t *testing.T) {
	_, dbPath, scanDir := findingsFixture(t, "null-deref", "001_src_a_c_13.md")

	// A verdict was persisted, but a stale unclassified candidate copy and a
	// dismissed file were left behind in findings/ (the 0.3.5 state).
	writeFinding(t, dbPath, scanDir, "confirmed", "13")
	stale := filepath.Join(scanDir, report.FindingsDir, "null-deref")
	for _, n := range []string{"002_src_a_c_20.md", "003_src_a_c_31_dismissed.md"} {
		if err := os.WriteFile(filepath.Join(stale, n), []byte("# leftover\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(context.Background(), []string{
			"--db", dbPath, "--audit", "--scan-id", fixtureScanID, "--output-dir", scanDir,
		})
	})
	if exitCode != 0 {
		t.Fatalf("audit failed: %s", stdout)
	}
	var out struct {
		FindingsSynced struct {
			Written int `json:"written"`
			Removed int `json:"removed"`
		} `json:"findings_synced"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("audit response is not JSON: %s", stdout)
	}
	if out.FindingsSynced.Written != 1 || out.FindingsSynced.Removed != 2 {
		t.Errorf("findings_synced = %+v, want written=1 removed=2", out.FindingsSynced)
	}
	names := findingFiles(t, scanDir, "null-deref")
	if len(names) != 1 || names[0] != "001_src_a_c_13_confirmed.md" {
		t.Fatalf("findings dir = %v, want only the confirmed verdict", names)
	}
}

// "Every candidate must get a finding" becomes machine-checkable: a bulk
// exclusion the agent only narrated leaves candidates with no persisted verdict,
// and the audit response says so.
func TestReportAudit_WarnsOnUnclassifiedCandidates(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{
		ScanID: fixtureScanID, VulnType: "null-deref", SeedCount: 223, FinalCount: 223,
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	scanDir := filepath.Join(root, "scans", fixtureScanID)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		t.Fatal(err)
	}
	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--audit", "--scan-id", fixtureScanID, "--output-dir", scanDir,
		})
	})
	if exitCode != 0 {
		t.Fatalf("audit failed: %s", stdout)
	}
	var out struct {
		Unclassified int    `json:"unclassified_candidates"`
		Warning      string `json:"warning"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("audit response is not JSON: %s", stdout)
	}
	if out.Unclassified != 223 {
		t.Errorf("unclassified_candidates = %d, want 223", out.Unclassified)
	}
	if !strings.Contains(out.Warning, "no persisted verdict") {
		t.Errorf("expected an explicit warning, got %q", out.Warning)
	}
}
