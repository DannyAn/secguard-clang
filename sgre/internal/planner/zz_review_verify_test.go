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

// reviewFixture pins four flow-sensitive false-negative cases that were found in
// a review pass: a kill confined to one branch must not suppress the null source
// on the other branch, an early return must not hide a later explicit NULL, and
// a branch-copy / branch-realloc must not clear the freed state on the other
// branch.
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

// Case B: early-return guard then explicit NULL. The EARLY_RETURN guard scope
// is cut off at the later p = NULL reassignment (guardScopeEnd), so the
// definite null deref is kept. Expect KEPT.
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

func TestReview_BranchSensitiveKeptCandidates(t *testing.T) {
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
	want := map[string][]string{
		"null-deref":     {"a_null_branch_kill", "b_guard_then_null"},
		"use-after-free": {"c_uaf_branch_copy"},
		"double-free":    {"d_doublefree_branch"},
	}
	for _, vt := range []string{"null-deref", "use-after-free", "double-free"} {
		result, err := pl.Plan(ctx, vt)
		if err != nil {
			t.Fatalf("plan %s: %v", vt, err)
		}
		kept := map[string]bool{}
		for _, c := range result.Candidates {
			kept[c.Target.Function] = true
		}
		for _, fn := range want[vt] {
			if !kept[fn] {
				t.Errorf("%s: expected %q to be kept (recall), got %v", vt, fn, candidateNames(result))
			}
		}
	}
}
