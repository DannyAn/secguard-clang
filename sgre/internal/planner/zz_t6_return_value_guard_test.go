//go:build !nosqlite

package planner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// planNDFixture runs the full null-deref pipeline over one testdata fixture.
func planNDFixture(t *testing.T, fixture string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", fixture)); err != nil {
		t.Fatalf("index %s: %v", fixture, err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)

	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}
	return res
}

// TestNullDeref_ReturnValueGuard locks the return-value null-guard fixpoint
// (issue #289 T6): `p = find_node(k); if (p == NULL) return; p->field = 1;`
// must not surface a null-deref candidate, while the unguarded variant must.
func TestNullDeref_ReturnValueGuard(t *testing.T) {
	res := planNDFixture(t, "tc_nd_ret_guard.c")

	if c := candidateForFunc(t, res, "tc_nd_ret_guard"); c != nil {
		t.Errorf("tc_nd_ret_guard is null-guarded before use; must not be a candidate, got var=%s level=%s", c.Target.Variable, c.SuspicionLevel)
	}
	if c := candidateForFunc(t, res, "tc_nd_ret_guard_bad"); c == nil {
		t.Errorf("tc_nd_ret_guard_bad dereferences a maybe-NULL return with no guard; must still be a candidate")
	}
}
