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

// uafFixture exercises the statement-level-CFG lifetime filter: a genuine
// use-after-free (free then use on the same path) must be kept, while a free
// and use in mutually exclusive branches (line-ordered but unreachable) must be
// suppressed.
const uafFixture = `#include <stdlib.h>

int tp_use_after_free(void) {
    char *p = (char *)malloc(16);
    free(p);
    *p = 'x';
    return 0;
}

int fp_branch_exclusive(int flag) {
    char *p = (char *)malloc(16);
    if (flag) {
        free(p);
    } else {
        *p = 'x';
    }
    return 0;
}

int fp_reassign_after_free(void) {
    char *p = (char *)malloc(16);
    free(p);
    p = (char *)malloc(32);
    *p = 'x';
    return 0;
}
`

func TestLifetimeFilter_CFGReachability(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "uaf.c")
	if err := os.WriteFile(path, []byte(uafFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "use-after-free")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if !kept["tp_use_after_free"] {
		t.Errorf("expected genuine use-after-free tp_use_after_free to be kept, got %v", candidateNames(result))
	}
	if kept["fp_branch_exclusive"] {
		t.Errorf("expected branch-exclusive fp_branch_exclusive to be suppressed, got %v", candidateNames(result))
	}
	if kept["fp_reassign_after_free"] {
		t.Errorf("expected fp_reassign_after_free (free then reassign) to be suppressed, got %v", candidateNames(result))
	}
}
