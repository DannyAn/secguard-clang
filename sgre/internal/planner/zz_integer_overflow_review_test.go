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

func planIntegerOverflow(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "io_review.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewIntegerOverflowDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "integer-overflow")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

func candidateFuncs(t *testing.T, result *PlanResult) map[string]bool {
	t.Helper()
	m := map[string]bool{}
	for _, c := range result.Candidates {
		m[c.Target.Function] = true
	}
	return m
}

// IO-05: a calloc-family wrapper (VOS_CALLOC_F) carries the same implicit
// product as calloc(n, m) and must be flagged.
func TestIntOverflowReview_WrappedCalloc(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct { int x; } T;
void *VOS_CALLOC_F(size_t n, size_t s) { return calloc(n, s); }
void wrapped(size_t n) {
    T *p = (T *)VOS_CALLOC_F(n, sizeof(T));
    (void)p;
}
`
	has := candidateFuncs(t, planIntegerOverflow(t, src))
	if !has["wrapped"] {
		t.Errorf("wrapped (VOS_CALLOC_F(n, sizeof(T))) should be flagged, got %v", has)
	}
}

// IO-06: a call_expression as a product factor must not be ignored.
func TestIntOverflowReview_CallFactor(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct { int x; } T;
size_t get_len(void) { return 0; }
void call_factor(void) {
    T *p = malloc(get_len() * sizeof(T));
    (void)p;
}
`
	has := candidateFuncs(t, planIntegerOverflow(t, src))
	if !has["call_factor"] {
		t.Errorf("call_factor (get_len() * sizeof(T)) should be flagged, got %v", has)
	}
}

// IO-14: calloc(n, m) guarded by `if (n < 100 && m < 100)` must be suppressed —
// the candidate must not carry the calloc function name as an operand.
func TestIntOverflowReview_CallocGuardSuppressed(t *testing.T) {
	src := `#include <stdlib.h>
void calloc_guarded(size_t n, size_t m) {
    if (n < 100 && m < 100) {
        char *p = calloc(n, m);
        (void)p;
    }
}
`
	has := candidateFuncs(t, planIntegerOverflow(t, src))
	if has["calloc_guarded"] {
		t.Errorf("calloc_guarded (n<100 && m<100, calloc(n,m)) should be suppressed, got %v", has)
	}
}

// IO-11: a guard inside a non-dominating branch must not be trusted.
func TestIntOverflowReview_NonDominatingGuard(t *testing.T) {
	src := `#include <stdlib.h>
int get_large(void) { return 1 << 30; }
void nondom(int cond, int n) {
    if (cond) {
        if (n < 100) {}
    }
    char *p = malloc(n * get_large());
    (void)p;
}
`
	has := candidateFuncs(t, planIntegerOverflow(t, src))
	if !has["nondom"] {
		t.Errorf("nondom (guard inside if(cond) does not dominate malloc) should be kept, got %v", has)
	}
}

// IO-12: a guard followed by a reassignment must not be trusted.
func TestIntOverflowReview_ReassignAfterGuard(t *testing.T) {
	src := `#include <stdlib.h>
int get_large(void) { return 1 << 30; }
void reassign(int n) {
    if (n < 100) {
        n = get_large();
        char *p = malloc(n * 1024);
        (void)p;
    }
}
`
	has := candidateFuncs(t, planIntegerOverflow(t, src))
	if !has["reassign"] {
		t.Errorf("reassign (n reassigned large inside the guard) should be kept, got %v", has)
	}
}

// IO-19/20: a field guard and a conjunction guard both bound their operands, so
// `if (s->len < 100 && n < 100) malloc(s->len * n)` is suppressed.
func TestIntOverflowReview_FieldAndConjunctionGuard(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct { size_t len; } S;
void field_guard(S *s, size_t n) {
    if (s->len < 100 && n < 100) {
        char *p = malloc(s->len * n);
        (void)p;
    }
}
`
	has := candidateFuncs(t, planIntegerOverflow(t, src))
	if has["field_guard"] {
		t.Errorf("field_guard (s->len<100 && n<100) should be suppressed, got %v", has)
	}
}
