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

// runNullPlan indexes a fixture and runs the null-deref pipeline end to end.
func runNullPlan(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// TestMustNull_BranchExclusiveNotDefinite pins the must-lattice fix: `p = NULL`
// on one branch and `p = &x` on the other is only POSSIBLY null at the join, so
// it must NOT be reported as a certain null-deref (has_definite_null).
func TestMustNull_BranchExclusiveNotDefinite(t *testing.T) {
	src := `#include <stdlib.h>
int f(int c) {
    int *p;
    if (c) { p = NULL; } else { p = &c; }
    return *p;
}
`
	result := runNullPlan(t, src)
	found := false
	for _, c := range result.Candidates {
		if c.Target.Function != "f" {
			continue
		}
		found = true
		if c.HasDefiniteNull {
			t.Errorf("f must NOT carry has_definite_null: p is NULL only on the c branch, not on every path")
		}
	}
	if !found {
		t.Errorf("expected f to be kept as a may-null candidate, got %v", candidateNames(result))
	}
}

// TestReturnNullable_CallResultGen pins the RETURN propagation fix: a deref of a
// call result whose callee returns a possibly-null value (here `return q` where
// q = malloc) must survive the convergence stage.
func TestReturnNullable_CallResultGen(t *testing.T) {
	src := `#include <stdlib.h>
static char *maybe_null(void) {
    char *q = (char *)malloc(8);
    return q;
}
int f(void) {
    char *p = maybe_null();
    return *p;
}
`
	result := runNullPlan(t, src)
	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}
	if !kept["f"] {
		t.Errorf("expected f (deref of a possibly-null call result) to be kept, got %v", candidateNames(result))
	}
}

// TestLifetime_BranchExclusiveNotConfirmed pins the must-tier downgrade: a free
// and a use on mutually-exclusive branches (two separate ifs x vs !x) must be
// kept as a suspicion, not promoted to confirmed by the path-insensitive CFG.
func TestLifetime_BranchExclusiveNotConfirmed(t *testing.T) {
	src := `#include <stdlib.h>
int f(int x) {
    char *p = (char *)malloc(16);
    if (x) { free(p); }
    if (!x) { *p = 'x'; }
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "uaf.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
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

	found := false
	for _, c := range result.Candidates {
		if c.Target.Function != "f" {
			continue
		}
		found = true
		if c.SuspicionLevel == "confirmed" {
			t.Errorf("f must NOT be confirmed: free and use are on mutually-exclusive branches (x vs !x)")
		}
	}
	if !found {
		t.Errorf("expected f to be kept (may-reachable, needs AI confirmation), got %v", candidateNames(result))
	}
}
