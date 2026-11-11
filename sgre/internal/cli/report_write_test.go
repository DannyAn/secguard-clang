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

// TestReportWriteJSONReportsDuplicates pins the #217 duplicate notice: a second
// write of the same finding (even one that omits the function name) updates the
// existing row, reports it under `duplicates`, and never adds a second finding.
func TestReportWriteJSONReportsDuplicates(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(d)
	scanID := "sc_2026-01-01_000000_abcdef"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "resource-leak", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	write := func(body string) map[string]any {
		path := filepath.Join(root, "batch.json")
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		stdout, _, code := captureOutput(func() int {
			return runReportCmd(ctx, []string{"--db", dbPath, "--write-json", path, "--scan-id", scanID})
		})
		if code != 0 {
			t.Fatalf("write failed: %s", stdout)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("write output is not JSON: %s", stdout)
		}
		return out
	}

	payload := `[{"rule_id":"CWE-404","severity":"high","confidence":90,"status":"confirmed","file":"a.c","line":10,"function":"f","variable":"fd","summary":"leaked fd"}]`
	first := write(payload)
	if first["duplicates"] != float64(0) || first["findings_written"] != float64(1) {
		t.Fatalf("first write = %+v, want duplicates 0 / written 1", first)
	}

	// Same location, function omitted: the retry must update, not duplicate.
	retry := write(`[{"rule_id":"CWE-404","severity":"high","confidence":90,"status":"confirmed","file":"a.c","line":10,"function":"","variable":"fd","summary":"leaked fd (retry)"}]`)
	if retry["duplicates"] != float64(1) || retry["findings_written"] != float64(1) {
		t.Fatalf("retry = %+v, want duplicates 1 / written 1", retry)
	}
	written, _ := retry["written"].([]any)
	if len(written) != 1 {
		t.Fatalf("written = %+v, want one entry", retry["written"])
	}
	if entry, _ := written[0].(map[string]any); entry["duplicate"] != true {
		t.Errorf("written entry must be flagged duplicate: %+v", written[0])
	}

	d, err = db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	all, err := db.NewStore(d).ListFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 finding after the duplicate retry, got %d", len(all))
	}
	// An empty function on a retry must NOT erase the name already persisted
	// (metadata regression); a non-empty correction still refreshes it.
	if all[0].FunctionName != "f" {
		t.Errorf("an empty retry function must preserve the persisted name, got %q", all[0].FunctionName)
	}
	corrected := write(`[{"rule_id":"CWE-404","severity":"high","confidence":90,"status":"confirmed","file":"a.c","line":10,"function":"f2","variable":"fd","summary":"leaked fd (corrected)"}]`)
	if corrected["duplicates"] != float64(1) {
		t.Fatalf("corrected write = %+v, want duplicates 1", corrected)
	}
	all, err = db.NewStore(d).ListFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].FunctionName != "f2" {
		t.Errorf("a non-empty retry function must refresh the row, got %+v", all)
	}
}

// TestReportWriteJSONDismissedPersisted pins issue #261 item 10: a dismissed
// verdict is NOT written to the findings table (skipped_dismissed), but it IS
// persisted to the candidate_verdicts ledger — reported under the unambiguous
// `dismissed_persisted` field (an alias of dismissed_written) so a consumer
// cannot misread "skipped" as "never persisted".
func TestReportWriteJSONDismissedPersisted(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(d)
	scanID := "sc_2026-01-01_000000_abc123"
	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	path := filepath.Join(root, "batch.json")
	payload := `[{"rule_id":"CWE-476","status":"dismissed","file":"a.c","line":7,"function":"f","variable":"p","reasoning":"guarded"}]`
	if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := captureOutput(func() int {
		return runReportCmd(ctx, []string{"--db", dbPath, "--write-json", path, "--scan-id", scanID})
	})
	if code != 0 {
		t.Fatalf("write failed: %s", stdout)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("write output is not JSON: %s", stdout)
	}
	if out["skipped_dismissed"] != float64(1) {
		t.Errorf("skipped_dismissed = %v, want 1", out["skipped_dismissed"])
	}
	if out["findings_written"] != float64(0) {
		t.Errorf("findings_written = %v, want 0 (dismissed is not a finding)", out["findings_written"])
	}
	if out["dismissed_persisted"] != float64(1) {
		t.Errorf("dismissed_persisted = %v, want 1 (verdict must land in candidate_verdicts)", out["dismissed_persisted"])
	}
	if out["dismissed_written"] != float64(1) {
		t.Errorf("dismissed_written = %v, want 1", out["dismissed_written"])
	}
}
