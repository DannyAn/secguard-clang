//go:build !nosqlite

package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

// Issue #253 P2-6: `status` must reconcile with `report --audit`. Two things
// broke that: the census was unscoped (findings from older scans persisted) and
// its buckets did not mirror Finding.FinalStatus() (a reviewed-out row kept its
// first-pass status). The counts below are scan-scoped and use the same
// dismissal set as FinalStatus.
func TestStatusVerdictCountsReconcileAudit(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "sgre.db")
	store, err := openStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.BeginScanRun(ctx, "sc_old"); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginScanRun(ctx, "sc_new"); err != nil {
		t.Fatal(err)
	}
	insert := func(scanID, status, review string) {
		t.Helper()
		if _, err := store.DB().ExecContext(ctx,
			`INSERT INTO findings (rule_id, vuln_type, severity, status, file_path, line_number, scan_id, review_status)
			 VALUES ('CWE-787', 'buffer-overflow', 'high', ?, 'a.c', 1, ?, ?)`,
			status, scanID, review); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
	}
	// Historical scan: must not leak into the current scan's census.
	insert("sc_old", "confirmed", "")
	// Current scan: one actionable confirmed, one dismissed confirmed.
	insert("sc_new", "confirmed", "")
	insert("sc_new", "confirmed", "dismissed")
	// Machine verdicts: unreviewed and reviewed-confirmed count as actionable;
	// dismissed / false_positive are reviewed out.
	insert("sc_new", "auto-confirmed", "")
	insert("sc_new", "auto-confirmed", "dismissed")
	insert("sc_new", "auto-confirmed", "false_positive")
	insert("sc_new", "auto-confirmed", "confirmed")
	store.Close()

	stdout, _, code := captureOutput(func() int {
		return runStatusCmd(ctx, []string{"--db", dbPath})
	})
	if code != 0 {
		t.Fatalf("status exit=%d, out=%s", code, stdout)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("status output is not JSON: %v\n%s", err, stdout)
	}
	if out["scan_id"] != "sc_new" {
		t.Errorf("scan_id = %v, want sc_new", out["scan_id"])
	}
	want := map[string]float64{
		"findings_count":           6,
		"confirmed_findings_count": 1,
		"auto_confirmed_count":     2,
		"reviewed_out_count":       3,
	}
	for key, w := range want {
		if got, _ := out[key].(float64); got != w {
			t.Errorf("%s = %v, want %v (out=%v)", key, out[key], w, out)
		}
	}
}
