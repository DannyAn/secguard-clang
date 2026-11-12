package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestGenerateScanID_Format(t *testing.T) {
	re := regexp.MustCompile(`^sc_\d{4}-\d{2}-\d{2}_\d{6}_[0-9a-f]{6}$`)
	for i := 0; i < 100; i++ {
		id := generateScanID()
		if !re.MatchString(id) {
			t.Fatalf("scan ID %q does not match expected format", id)
		}
	}
}

func TestGenerateScanID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := generateScanID()
		if ids[id] {
			t.Fatalf("duplicate scan ID generated: %q", id)
		}
		ids[id] = true
	}
}

func TestWriteDismissed_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	summary := DismissedSummary{
		ScanID:       "2026-08-13_000000_0000",
		TotalDropped: 3,
		ByVulnType: []VulnTypeDismissed{
			{
				VulnerabilityType: "null-deref",
				DroppedCount:      3,
				DroppedByReason:   map[string]int{"nullable_source": 2, "guard": 1},
			},
		},
	}

	if err := WriteDismissed(dir, summary); err != nil {
		t.Fatalf("WriteDismissed failed: %v", err)
	}

	path := filepath.Join(dir, DismissedFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("dismissed file not written: %v", err)
	}

	var got DismissedSummary
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("dismissed file not valid JSON: %v", err)
	}
	if got.TotalDropped != 3 || len(got.ByVulnType) != 1 {
		t.Fatalf("unexpected dismissed summary: %+v", got)
	}
	if got.ByVulnType[0].DroppedCount != 3 || got.ByVulnType[0].DroppedByReason["nullable_source"] != 2 {
		t.Fatalf("drop summary should be persisted, got %+v", got.ByVulnType[0])
	}
}

// TestScansRootFromDBPath pins the issue #264 #14 rule: the scans root is
// derived from the DB path (its directory is the SgreDir layer), so an
// explicit --db relocates the scan artifacts with the database instead of
// leaving them in the launching cwd — and for the canonical layout the
// result is exactly ScansRoot(projectRoot), keeping the default behavior
// unchanged.
func TestScansRootFromDBPath(t *testing.T) {
	root := t.TempDir()
	canonical := GetDbPath(root)
	if got, want := ScansRootFromDBPath(canonical), ScansRoot(root); got != want {
		t.Errorf("canonical layout: ScansRootFromDBPath(%q) = %q, want %q", canonical, got, want)
	}
	if got, want := ScansRootFromDBPath("/tmp/x.db"), "/scans"; got != want {
		t.Errorf("explicit db: ScansRootFromDBPath = %q, want %q", got, want)
	}
}

// TestNewScanOutputIn pins the artifact-follows-DB construction: the per-scan
// directory lands under the given scans root while RootDir (the display-path
// base) stays the project root.
func TestNewScanOutputIn(t *testing.T) {
	scansRoot := filepath.Join(t.TempDir(), "scans")
	rootDir := t.TempDir()
	so := NewScanOutputIn(scansRoot, rootDir)
	if so.RootDir != rootDir {
		t.Errorf("RootDir = %q, want %q", so.RootDir, rootDir)
	}
	if filepath.Dir(so.ScanDir) != scansRoot {
		t.Errorf("ScanDir = %q, want a child of %q", so.ScanDir, scansRoot)
	}
	if so.SarifPath != filepath.Join(so.ScanDir, SarifFile) {
		t.Errorf("SarifPath = %q, want inside ScanDir", so.SarifPath)
	}
}
