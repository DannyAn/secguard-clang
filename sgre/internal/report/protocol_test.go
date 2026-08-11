package report

import (
	"regexp"
	"testing"
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
