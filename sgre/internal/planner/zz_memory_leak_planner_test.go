//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestMemoryLeak_OverwriteThenFreeSurvivesPlan pins the C3 fix: the detector
// emits a RELEASE for the SECOND allocation (`p = malloc(); p = malloc();
// free(p)` releases the second block) but the FIRST block still leaks. The
// ReleaseFilter must correlate the release to the released alloc site (via
// alloc_line) and NOT drop the leaked first site at coarse (function, variable)
// granularity.
func TestMemoryLeak_OverwriteThenFreeSurvivesPlan(t *testing.T) {
	src := `#include <stdlib.h>

int overwrite_then_free(void) {
    int *p = (int *)malloc(16);
    p = (int *)malloc(32);
    free(p);
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "leak.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)

	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "memory-leak")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	caught := map[string]int{}
	for _, c := range res.Candidates {
		caught[c.Target.Function]++
	}
	if caught["overwrite_then_free"] == 0 {
		t.Errorf("overwrite_then_free: the leaked first allocation was dropped; candidates=%v", candidateNames(res))
	}
}
