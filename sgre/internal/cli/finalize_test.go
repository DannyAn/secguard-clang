//go:build !nosqlite

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// TestListStagedVerdictFilesFilters pins the replay admission rule: only a
// bare JSON array (first byte `[`) that is NOT a settlement report/chunk is a
// replayable verdict file. Settlement reports and chunks are JSON objects and
// must never be replayed as verdicts.
func TestListStagedVerdictFilesFilters(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sgre.db")
	tmp := filepath.Join(filepath.Dir(dbPath), ".tmp")
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"null-deref.json":      `[{"rule_id":"CWE-476","status":"confirmed","file":"a.c","line":1}]`,
		"buffer-overflow.json": "[\n {\"rule_id\":\"CWE-787\"}\n]",
		"whitespace-led.json":  "\n\t[{\"rule_id\":\"CWE-787\"}]",
		"sub1-report.json":     `{"format_version":1,"subagent_id":"sub1"}`,
		"sub1-chunk-1.json":    `{"format_version":1,"subagent_id":"sub1"}`,
		"notes.json":           `{"not":"an array"}`,
		"readme.txt":           `[`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got := listStagedVerdictFiles(dbPath)
	if len(got) != 3 {
		t.Fatalf("listStagedVerdictFiles returned %v, want exactly the three verdict arrays", got)
	}
	names := map[string]bool{}
	for _, p := range got {
		names[filepath.Base(p)] = true
	}
	if !names["null-deref.json"] || !names["buffer-overflow.json"] || !names["whitespace-led.json"] {
		t.Errorf("replayable files = %v, want null-deref.json, buffer-overflow.json and whitespace-led.json", got)
	}
}

// TestFinalizeReplaysStagedVerdictsAndProducesSarif is the end-to-end recovery
// contract (issue #283 R6): an interrupted scan whose AI verdicts are staged as
// JSON arrays under .sgre/.tmp/ is closed out by `secguard finalize`, which
// replays the verdicts, settles the type, regenerates result.sarif and findings/,
// and reports the replay/self-check counts in one envelope.
func TestFinalizeReplaysStagedVerdictsAndProducesSarif(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(d)
	scanID := "sc_2026-11-16_150000_abc123"
	if err := store.BeginScanRun(ctx, scanID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 2, FinalCount: 2, AIStageStatus: "pending"}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	tmp := filepath.Join(filepath.Dir(dbPath), ".tmp")
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	staged := `[
		{"rule_id":"CWE-476","vuln_type":"null-deref","severity":"high","confidence":90,"status":"confirmed","file":"a.c","line":1,"function":"f","variable":"p","summary":"deref of possibly-null p"},
		{"rule_id":"CWE-476","vuln_type":"null-deref","status":"dismissed","file":"b.c","line":2,"function":"g","variable":"q","reasoning":"guarded"}
	]`
	if err := os.WriteFile(filepath.Join(tmp, "null-deref.json"), []byte(staged), 0644); err != nil {
		t.Fatal(err)
	}
	// A settlement report in the same dir must be ignored by the replay.
	if err := os.WriteFile(filepath.Join(tmp, "sub-report.json"), []byte(`{"format_version":1,"subagent_id":"sub1"}`), 0644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(root, "scans", scanID)
	stdout, _, code := captureOutput(func() int {
		return runFinalizeCmd(ctx, []string{"--scan-id", scanID, "--db", dbPath, "--output-dir", outDir})
	})
	if code != 0 {
		t.Fatalf("finalize exit=%d, want 0: %s", code, stdout)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("finalize output is not JSON: %s", stdout)
	}
	if out["status"] != "ok" {
		t.Errorf("finalize status = %v, want ok (envelope: %s)", out["status"], stdout)
	}
	if out["pending_replay_files"] != float64(1) {
		t.Errorf("pending_replay_files = %v, want 1", out["pending_replay_files"])
	}
	if out["findings_count"] != float64(1) {
		t.Errorf("findings_count = %v, want 1", out["findings_count"])
	}
	completed, _ := out["completed_types"].([]any)
	if len(completed) != 1 || completed[0] != "null-deref" {
		t.Errorf("completed_types = %v, want [null-deref]", out["completed_types"])
	}

	sarifPath := filepath.Join(outDir, "result.sarif")
	info, err := os.Stat(sarifPath)
	if err != nil {
		t.Fatalf("result.sarif was not produced: %v", err)
	}
	if info.Size() == 0 {
		t.Errorf("result.sarif is empty")
	}
	if data, err := os.ReadFile(sarifPath); err == nil && !json.Valid(data) {
		t.Errorf("result.sarif is not valid JSON")
	}
}

// TestFinalizeUnknownScanIDFails pins that finalize never fabricates artifacts
// for a scan id that never ran.
func TestFinalizeUnknownScanIDFails(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	stdout, _, code := captureOutput(func() int {
		return runFinalizeCmd(ctx, []string{"--scan-id", "sc_2026-11-16_150000_abcdef", "--db", dbPath, "--output-dir", filepath.Join(root, "scans")})
	})
	if code == 0 {
		t.Fatalf("finalize with unknown scan id must exit non-zero, got 0: %s", stdout)
	}
}
