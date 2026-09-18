package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// runUAFDetectors indexes a fixture and runs only the use-after-free and
// double-free detectors (runIndexAndDetect does not include them).
func runUAFDetectors(t *testing.T, fixture string) db.Store {
	t.Helper()
	store := indexFixtureForInjection(t, fixture)
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	if _, err := NewUseAfterFreeDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("use_after_free detect: %v", err)
	}
	if _, err := NewDoubleFreeDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("double_free detect: %v", err)
	}
	return store
}

func assertNoEventOfType(t *testing.T, store db.Store, eventType, fixture string) {
	t.Helper()
	evs, err := store.ListEventsByType(context.Background(), eventType)
	if err != nil {
		t.Fatalf("list %s: %v", eventType, err)
	}
	for _, e := range evs {
		t.Errorf("%s: unexpected %s event: %s", fixture, eventType, e.Properties)
	}
}

// TestUAF_FieldFreeReassign_NoEvents pins the "field-free function" fix: a
// function named health_free_content (free in the MIDDLE) frees a FIELD of its
// argument, not the argument itself. Calling it then reassigning the field must
// produce no use-after-free / double-free candidate.
func TestUAF_FieldFreeReassign_NoEvents(t *testing.T) {
	store := runUAFDetectors(t, "tc_uaf_field_free_reassign.c")
	assertNoEventOfType(t, store, "USE_AFTER_FREE", "tc_uaf_field_free_reassign")
	assertNoEventOfType(t, store, "DOUBLE_FREE", "tc_uaf_field_free_reassign")
}

// TestUAF_DisjointBranches_NoUseAtFreeLine pins the "free's own argument is not
// a use" fix: the second free(g.data) must not count g.data as a use, so the
// detector reports no "freed then used at the second free's own line" event.
func TestUAF_DisjointBranches_NoUseAtFreeLine(t *testing.T) {
	store := runUAFDetectors(t, "tc_uaf_disjoint_branches.c")
	ctx := context.Background()
	evs, _ := store.ListEventsByType(ctx, "USE_AFTER_FREE")
	for _, e := range evs {
		t.Errorf("tc_uaf_disjoint_branches: unexpected USE_AFTER_FREE event: %s", e.Properties)
	}
}

// TestUAF_LinkedListDelete_NoCandidates pins the linked-list deletion fix: a
// custom freeing wrapper (pktdrp_free_tbl_res, not a built-in deallocator) frees
// its argument, and the deletion routine reassigns the alias (pre_item) before
// the free. Two independent root causes had to be fixed:
//  1. findUseSites counted the wrapper's argument as a use (evidence layer).
//  2. expandGenToAliases propagated a stale alias past its reassignment
//     (planner layer) — freeing item dangled pre_item even though pre_item had
//     been reassigned to g_pktdrp_tbl two lines earlier.
//
// The full pipeline (graph + detector + planner) must yield ZERO use-after-free
// candidates. This test is the regression guard for both fixes together.
func TestUAF_LinkedListDelete_NoCandidates(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc_uaf_linked_list_delete.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewAliasBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "use-after-free")
	if err != nil {
		t.Fatalf("plan use-after-free: %v", err)
	}
	if res.CandidateCount() != 0 {
		t.Errorf("expected 0 use-after-free candidates (linked-list delete), got %d", res.CandidateCount())
		for _, c := range res.Candidates {
			t.Logf("  var=%q line=%d suspicion=%s", c.Target.Variable, c.Target.Line, c.SuspicionLevel)
		}
	}
}

// TestUAF_DisjointBranches_NoConvergedCandidates runs the full double-free /
// use-after-free pipelines (real parser + graph + filters) and asserts the two
// mutually-exclusive frees converge to ZERO candidates: the flow filters must
// dismiss a free whose branch returns before the second free is reached.
func TestUAF_DisjointBranches_NoConvergedCandidates(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc_uaf_disjoint_read.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	NewDoubleFreeDetector(store, p, logger).Detect(ctx)
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	pl := planner.NewPlanner(store, p, logger)
	for _, vt := range []string{"double-free", "use-after-free"} {
		res, err := pl.Plan(ctx, vt)
		if err != nil {
			t.Fatalf("plan %s: %v", vt, err)
		}
		if res.CandidateCount() != 0 {
			t.Errorf("%s: expected 0 candidates (mutually-exclusive frees), got %d", vt, res.CandidateCount())
			for _, c := range res.Candidates {
				t.Logf("  var=%q line=%d", c.Target.Variable, c.Target.Line)
			}
		}
	}
}
