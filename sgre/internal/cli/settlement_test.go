//go:build !nosqlite

package cli

import (
	"context"
	"math"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestNormalizeSettlementRange(t *testing.T) {
	cases := map[string]string{"": "all", "  ": "all", "all": "all", "1-69": "1-69"}
	for in, want := range cases {
		if got := normalizeSettlementRange(in); got != want {
			t.Errorf("normalizeSettlementRange(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSuggestedBatchSizeAndBatches(t *testing.T) {
	if got := suggestedBatchSize(0.63); got != 19 {
		t.Errorf("suggestedBatchSize(0.63) = %d, want 19 (floor(12/0.63))", got)
	}
	if got := suggestedBatchSize(1.0); got != 12 {
		t.Errorf("suggestedBatchSize(1.0) = %d, want 12", got)
	}
	if got := suggestedBatchSize(20.0); got != 1 {
		t.Errorf("suggestedBatchSize(20.0) = %d, want 1 (clamped)", got)
	}
	if got := suggestedBatches(560, 19); got != 30 {
		t.Errorf("suggestedBatches(560, 19) = %d, want 30", got)
	}
	if got := suggestedBatches(0, 19); got != 0 {
		t.Errorf("suggestedBatches(0, 19) = %d, want 0", got)
	}
}

func TestSettlementAggregate(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	// null-deref: 12 opens across 19 classified candidates = 0.6316...
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_prev", VulnType: "null-deref", RangeStr: "all", SubagentID: "a",
		Written: 3, Dismissed: 16, EvidenceOpens: 12,
	}); err != nil {
		t.Fatal(err)
	}

	agg := settlementAggregate(ctx, store, "null-deref")
	if agg.sample != 1 {
		t.Errorf("sample = %d, want 1", agg.sample)
	}
	if math.Abs(agg.rType-12.0/19.0) > 1e-9 {
		t.Errorf("rType = %f, want %f", agg.rType, 12.0/19.0)
	}
	if agg.avgWallMS != 0 {
		t.Errorf("avgWallMS = %d, want 0 (no wall_ms recorded)", agg.avgWallMS)
	}

	// No history → fallback 0.30, sample 0.
	empty := settlementAggregate(ctx, store, "divide-by-zero")
	if empty.rType != settlementRTypeFallback || empty.sample != 0 {
		t.Errorf("empty aggregate = %+v, want fallback/sample0", empty)
	}
}

func TestEnrichPerTypeStatusAlreadyCovered(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	if _, err := store.InsertScanStat(ctx, &db.ScanStat{ScanID: "sc_test", VulnType: "uninit", SeedCount: 90, FinalCount: 90}); err != nil {
		t.Fatal(err)
	}
	// this scan already settled range 1-50
	if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
		ScanID: "sc_test", VulnType: "uninit", RangeStr: "1-50", SubagentID: "b",
		Written: 0, Dismissed: 50, EvidenceOpens: 0,
	}); err != nil {
		t.Fatal(err)
	}

	statuses, err := store.ListPerTypeStatus(ctx, "sc_test", func(string) []string { return []string{"CWE-457"} })
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := enrichPerTypeStatus(ctx, store, "sc_test", statuses)
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched, got %d", len(enriched))
	}
	e := enriched[0]
	if len(e.AlreadyCoveredRanges) != 1 || e.AlreadyCoveredRanges[0] != "1-50" {
		t.Errorf("already_covered_ranges = %v, want [1-50]", e.AlreadyCoveredRanges)
	}
	if e.VulnType != "uninit" || e.CandidateCount != 90 {
		t.Errorf("base status fields lost: %+v", e.PerTypeStatus)
	}
}

func TestPersistSettlementReports(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	project := t.TempDir()
	dbPath := project + "/.codeagent/secguard-clang/.sgre/sgre.db"
	tmp := project + "/.codeagent/secguard-clang/.sgre/.tmp"
	writeReport(t, tmp, "sub-a-report.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-69","cwe":"CWE-476","written":3,"dismissed":66,"source_reads":1,"evidence_opens":43,"repo_greps":0}]
	}`)
	writeReport(t, tmp, "sub-partial-report.json", `{"format_version":1,"subagent_id":"sub-p","scan_id":"sc_test"`)

	res := listSubagentReports(dbPath, "sc_test")
	if err := persistSettlementReports(ctx, store, res); err != nil {
		t.Fatal(err)
	}

	rows, err := store.ListSettlementStatsByScan(ctx, "sc_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 persisted row (partial excluded), got %d", len(rows))
	}
	if rows[0].VulnType != "null-deref" || rows[0].RangeStr != "1-69" || rows[0].EvidenceOpens != 43 || rows[0].Dismissed != 66 {
		t.Errorf("persisted row mismatch: %+v", rows[0])
	}

	// Re-persisting the same file must stay idempotent.
	if err := persistSettlementReports(ctx, store, listSubagentReports(dbPath, "sc_test")); err != nil {
		t.Fatal(err)
	}
	rows, _ = store.ListSettlementStatsByScan(ctx, "sc_test")
	if len(rows) != 1 {
		t.Fatalf("re-persist must not duplicate, got %d", len(rows))
	}
}
