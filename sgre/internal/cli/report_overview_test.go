//go:build !nosqlite

package cli

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestBuildScanOverview_ComputesDismissedTotal(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	if err := store.UpsertScanRun(ctx, &db.ScanRun{
		ScanID:           "sc_test",
		FilesIndexed:     2,
		FunctionsIndexed: 5,
		SeedCount:        20,
		FinalCount:       12,
	}); err != nil {
		t.Fatalf("upsert scan run: %v", err)
	}

	audits := []vulnAuditEntry{
		{VulnType: "buffer-overflow", SeedCount: 10, FinalCount: 8, AutoConfirmed: 2, Confirmed: 5},
		{VulnType: "null-deref", SeedCount: 10, FinalCount: 4, AutoConfirmed: 1, Confirmed: 2},
	}
	ov := buildScanOverview(ctx, store, "sc_test", nil, nil, audits)

	if got, want := ov.Candidates, 12; got != want {
		t.Errorf("candidates = %d, want %d", got, want)
	}
	if got, want := ov.AIConfirmed, 7; got != want {
		t.Errorf("ai confirmed = %d, want %d", got, want)
	}
	if got, want := ov.AIDismissed, 5; got != want {
		t.Errorf("dismissed = %d, want %d", got, want)
	}

	fields := ov.SummaryFields()
	if got, ok := fields["dismissed_total"].(int); !ok {
		t.Fatalf("summary missing dismissed_total: %v", fields)
	} else if got != 5 {
		t.Errorf("summary dismissed_total = %d, want 5", got)
	}
}
