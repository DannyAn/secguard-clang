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

// TEMP verification fixture - delete after review.
const reviewFixture = `#include <stdlib.h>

int g_int;

// Case A: null-deref branch kill leak. malloc may return NULL; when c==0 the
// p=&g kill does NOT run, so *p can be a NULL deref. Expect KEPT.
int a_null_branch_kill(int c) {
    int *p = (int *)malloc(sizeof(int));
    if (c) {
        p = &g_int;
    }
    return *p;
}

// Case B: early-return guard then explicit NULL. Line-range guard scope
// ignores the reassignment. Expect KEPT (definite null deref).
int b_guard_then_null(int *p) {
    if (p == NULL) {
        return 0;
    }
    p = NULL;
    return *p;
}

// Case C: UAF with branch copy. free(p); if (c) p = q; *p -> UAF when !c.
// Expect KEPT.
void c_uaf_branch_copy(int c, int *q) {
    int *p = (int *)malloc(sizeof(int));
    free(p);
    if (c) {
        p = q;
    }
    *p = 1;
}

// Case D: double-free with single-line conditional reassign between frees.
// free(p); if (c) p = malloc(4); free(p); -> double free when !c. Expect KEPT.
void d_doublefree_branch(int c) {
    int *p = (int *)malloc(sizeof(int));
    free(p);
    if (c) p = (int *)malloc(4);
    free(p);
}
`

func TestReview_FalseNegatives(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	defer p.CloseAll()

	dir := t.TempDir()
	path := filepath.Join(dir, "review.c")
	if err := os.WriteFile(path, []byte(reviewFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewAliasBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)

	pl := NewPlanner(store, p, logger)
	for _, vt := range []string{"null-deref", "use-after-free", "double-free"} {
		result, err := pl.Plan(ctx, vt)
		if err != nil {
			t.Fatalf("plan %s: %v", vt, err)
		}
		kept := map[string]bool{}
		for _, c := range result.Candidates {
			kept[c.Target.Function] = true
		}
		t.Logf("%s kept: %v", vt, candidateNames(result))
		for _, d := range result.Summary.Dropped {
			t.Logf("%s dropped: %s: %s", vt, d.FunctionName, d.Reason)
		}
		_ = kept
	}
}
