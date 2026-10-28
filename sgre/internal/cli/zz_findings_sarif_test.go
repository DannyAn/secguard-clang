package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestScanWritesFindingsSarif pins the contract that `secguard scan` writes
// findings.sarif alongside candidates.sarif. findings.sarif carries the
// pipeline-proved (auto-confirmed) verdicts that candidates.sarif excludes;
// without it a benchmark validator that only reads candidates.sarif sees
// auto-confirmed detections as phantom false negatives (the 41-FN regression
// that motivated this test).
func TestScanWritesFindingsSarif(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	cPath := filepath.Join(root, "test.c")
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

	scanDir := filepath.Join(root, ".codeagent", "secguard-clang", "scans", "sc_2026-01-01_000000_zztest")
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	if code := runScan(t, ctx, dbPath, scanDir, cPath); code != 0 {
		t.Fatalf("scan failed with code %d", code)
	}

	findingsSarif := filepath.Join(scanDir, "findings.sarif")
	data, err := os.ReadFile(findingsSarif)
	if err != nil {
		t.Fatalf("findings.sarif not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("findings.sarif is empty")
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("findings.sarif is not valid JSON: %v", err)
	}

	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("findings.sarif has no runs array")
	}
	run0, _ := runs[0].(map[string]interface{})
	if _, ok := run0["results"]; !ok {
		t.Error("findings.sarif run has no results key")
	}
	props, _ := run0["properties"].(map[string]interface{})
	if props == nil || props["stage"] != "findings" {
		t.Error("findings.sarif missing stage=findings property")
	}
}
