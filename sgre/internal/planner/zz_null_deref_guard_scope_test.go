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

func planNullDerefGuardScope(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "guard_scope.c")
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
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// TestNullDeref_GuardScope_ExitingReassign pins the guarded-global idiom: a
// whole-variable reassignment (`g = NULL`) that runs only on a branch that
// returns must NOT truncate the earlier `if (g == NULL) return` guard's scope,
// because the fall-through path never executes it. The previous line-order
// guardScopeEnd cut the scope at the dead reassignment and misreported the
// later dereference as a null-deref.
func TestNullDeref_GuardScope_ExitingReassign(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

typedef struct { uint32_t n; void *head; } third_pool_t;

third_pool_t *g_third_pool;

void *xyz_malloc(int mid, size_t n) { return malloc(n); }

int init_lock(void) { return 0; }

uint32_t guarded_global(uint32_t max_num)
{
    g_third_pool = xyz_malloc(0, sizeof(third_pool_t));
    if (g_third_pool == NULL) {
        return 1;
    }
    g_third_pool->n = max_num;
    g_third_pool->head = NULL;
    if (init_lock() != 0) {
        free(g_third_pool);
        g_third_pool = NULL;
        return 1;
    }
    if (g_third_pool->n > 10) {
        return 2;
    }
    return 0;
}
`
	result := planNullDerefGuardScope(t, src)
	if c := candidateForFunc(t, result, "guarded_global"); c != nil {
		t.Errorf("guarded_global should NOT be flagged (g_third_pool is null-guarded; the g_third_pool=NULL is on an exiting branch), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// TestNullDeref_GuardScope_ReachableReassign is the control: a whole-variable
// reassignment on the straight-line fall-through path must still truncate the
// guard scope, so a deref after it stays a (definite) null-deref.
func TestNullDeref_GuardScope_ReachableReassign(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

typedef struct { uint32_t n; } third_pool_t;

void *xyz_malloc(int mid, size_t n) { return malloc(n); }

uint32_t seq_reassign(uint32_t max_num)
{
    third_pool_t *p = xyz_malloc(0, sizeof(third_pool_t));
    if (p == NULL) {
        return 1;
    }
    p->n = max_num;
    p = NULL;
    return p->n;
}
`
	result := planNullDerefGuardScope(t, src)
	if c := candidateForFunc(t, result, "seq_reassign"); c == nil {
		t.Errorf("seq_reassign should STAY flagged (p = NULL on the fall-through path re-nulls p before the deref)")
	} else if !c.HasDefiniteNull {
		t.Errorf("seq_reassign's p is explicitly nulled before the deref, expected has_definite_null=true, got %v", c.HasDefiniteNull)
	}
}
