package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

// A type-filtered scan must narrow the PLAN stage (Issue #232's silently
// ignored positional argument) and record the applied scope in the scan JSON;
// the filters are validated before any expensive work.
func TestScanTypeFilter_NarrowsPlanAndEchoesScope(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		t.Fatal(err)
	}
	scanDir := filepath.Join(root, ".codeagent", "secguard-clang", "scans", "sc_2026-11-06_120000_abc123")

	config.SetTypeFilterOverride("")
	t.Cleanup(func() { config.SetTypeFilterOverride("") })

	stdout, _, code := captureOutput(func() int {
		return runScanCmd(ctx, []string{"--db", dbPath, "--output-dir", scanDir, cPath, "null-deref"})
	})
	if code != 0 {
		t.Fatalf("filtered scan failed: code=%d out=%s", code, stdout)
	}
	var out struct {
		TypeFilter    []string          `json:"type_filter"`
		AppliedTypes  []string          `json:"applied_types"`
		Candidates    map[string]int    `json:"candidates_by_type"`
		Completion    string            `json:"completion_state"`
		DisabledTypes []string          `json:"disabled_types"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("scan output is not JSON: %v\n%s", err, stdout)
	}
	if len(out.TypeFilter) != 1 || out.TypeFilter[0] != "null-deref" {
		t.Errorf("type_filter = %v, want [null-deref]", out.TypeFilter)
	}
	if len(out.AppliedTypes) != 1 || out.AppliedTypes[0] != "null-deref" {
		t.Errorf("applied_types = %v, want [null-deref]", out.AppliedTypes)
	}
	for typ := range out.Candidates {
		if typ != "null-deref" {
			t.Errorf("candidates_by_type contains %q; the plan must be narrowed to null-deref", typ)
		}
	}
}

func TestScanTypeFilter_RejectsUnknownTypeBeforeScanning(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)
	dbPath := filepath.Join(root, "sgre.db")

	config.SetTypeFilterOverride("")
	t.Cleanup(func() { config.SetTypeFilterOverride("") })

	stdout, _, code := captureOutput(func() int {
		return runScanCmd(ctx, []string{"--db", dbPath, cPath, "not-a-type"})
	})
	if code != 1 {
		t.Fatalf("unknown filter type must fail before scanning: code=%d out=%s", code, stdout)
	}
	if !strings.Contains(stdout, "unknown type-filter type") {
		t.Errorf("error must name the invalid filter, got %s", stdout)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Errorf("the scan must not create a DB for an invalid filter")
	}
}

// A registered type that [disabled_types] turns off must fail instead of
// completing a zero-type "clean" scan.
func TestScanTypeFilter_RejectsAllDisabledTypes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)
	dbPath := filepath.Join(root, "sgre.db")

	cfgPath := filepath.Join(root, "secguard.toml")
	if err := os.WriteFile(cfgPath, []byte("[disabled_types]\ntypes = [\"null-deref\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(cfgPath)
	config.SetTypeFilterOverride("")
	t.Cleanup(func() {
		config.SetExplicitPath("")
		config.SetTypeFilterOverride("")
	})

	stdout, _, code := captureOutput(func() int {
		return runScanCmd(ctx, []string{"--db", dbPath, cPath, "null-deref"})
	})
	if code != 1 {
		t.Fatalf("an all-disabled filter must fail: code=%d out=%s", code, stdout)
	}
	if !strings.Contains(stdout, "no enabled vulnerability type") {
		t.Errorf("error must explain the disabled filter, got %s", stdout)
	}
}
