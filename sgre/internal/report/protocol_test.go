package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestGenerateScanID_Format(t *testing.T) {
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}_\d{6}_[0-9a-f]{4}$`)
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
				Dropped: []planner.Dismissed{
					{FunctionName: "parse", VariableName: "hdr", Line: 10, Filter: "nullable_source", Reason: "no nullable source for variable hdr before line 10"},
				},
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
	if got.ByVulnType[0].Dropped[0].Reason == "" {
		t.Fatalf("drop reason should be persisted, got empty")
	}
}
