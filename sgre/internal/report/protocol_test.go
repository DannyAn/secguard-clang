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

// TestScansRootFromDBPath pins the consumer-side derivation: a canonical
// layout DB path maps back to exactly ScansRoot(projectRoot) — the rule
// `status` uses to locate a resolved DB's artifacts. The bare-path case
// documents the derivation's limit: it is only exact for canonical-layout
// paths, so callers resolving an explicit non-canonical --db must treat a
// miss as "artifacts not found" (the index_shards lookup degrades to nil),
// never as a location change — scan artifacts stay under the launching
// directory regardless of --db (issue #264 #14).
func TestScansRootFromDBPath(t *testing.T) {
	root := t.TempDir()
	canonical := GetDbPath(root)
	if got, want := ScansRootFromDBPath(canonical), ScansRoot(root); got != want {
		t.Errorf("canonical layout: ScansRootFromDBPath(%q) = %q, want %q", canonical, got, want)
	}
	if got, want := ScansRootFromDBPath("/tmp/x.db"), "/scans"; got != want {
		t.Errorf("bare db path: ScansRootFromDBPath = %q, want %q", got, want)
	}
}
