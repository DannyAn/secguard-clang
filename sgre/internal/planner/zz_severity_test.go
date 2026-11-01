//go:build !nosqlite

package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

// TestSeverityScaleDistribution pins the GAP-10 severity scale: the 28 types
// fall into the pyramid 6 critical / 6 high / 15 medium / 1 low (B5's
// unbounded-length-copy will add the 7th high, for 29 total). DoS classes sit
// in medium; write-primitive classes in critical; unchecked-return is the only
// low (robustness).
func TestSeverityScaleDistribution(t *testing.T) {
	counts := map[string]int{}
	for _, name := range AllVulnTypes() {
		spec, err := GetVulnTypeSpec(name)
		if err != nil || spec.DefaultSeverity == "" {
			t.Fatalf("type %q: missing DefaultSeverity", name)
		}
		counts[spec.DefaultSeverity]++
	}
	want := map[string]int{"critical": 6, "high": 6, "medium": 15, "low": 1}
	for sev, n := range want {
		if counts[sev] != n {
			t.Errorf("severity %q = %d types, want %d (full: %v)", sev, counts[sev], n, counts)
		}
	}
	if total := len(AllVulnTypes()); total != 28 {
		t.Errorf("expected 28 registered types, got %d", total)
	}
}

// TestSeverityFor_CategoryOverride pins that the per-category override wins over
// the type default (e.g. injection: command→critical, sql→high, xml→low).
func TestSeverityFor_CategoryOverride(t *testing.T) {
	cases := []struct{ typ, cat, want string }{
		{"injection", "command_injection", "critical"},
		{"injection", "sql_injection", "high"},
		{"injection", "xml_injection", "low"},
		{"injection", "crlf_injection", "critical"}, // falls back to type default
		{"null-deref", "", "medium"},
		{"unchecked-return", "", "low"},
		{"buffer-overflow", "heap_oob_write", "critical"},
		{"buffer-overflow", "bounded_copy_var_size", "high"}, // type default
		{"path-traversal", "world_writable_file", "medium"},
	}
	for _, c := range cases {
		if got := SeverityFor(c.typ, c.cat); got != c.want {
			t.Errorf("SeverityFor(%q, %q) = %q, want %q", c.typ, c.cat, got, c.want)
		}
	}
}

// TestSeverityFor_ConfigOverride pins that a [severity] override wins over the
// registry default (a user's explicit decision).
func TestSeverityFor_ConfigOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(cfgPath, []byte("[severity.overrides]\n\"null-deref\" = \"high\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	config.SetExplicitPath(cfgPath)
	defer config.SetExplicitPath("")
	if got := SeverityFor("null-deref", ""); got != "high" {
		t.Errorf("SeverityFor(null-deref) with override = %q, want high", got)
	}
	if got := SeverityFor("unchecked-return", ""); got != "low" {
		t.Errorf("SeverityFor(unchecked-return) (no override) = %q, want low", got)
	}
}
