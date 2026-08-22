//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestRangeFilter_DivideByZero pins the cross-assignment interval propagation:
// `d = 0; d = 1; x / d` must be suppressed (d is provably 1), while `d = 0` or
// `d = param` before the division must be kept.
func TestRangeFilter_DivideByZero(t *testing.T) {
	src := `#include <stdlib.h>

int fp_reassigned_nonzero(void) {
    int d = 0;
    d = 1;
    return 10 / d;
}

int tp_zero(void) {
    int d = 0;
    return 10 / d;
}

int tp_unknown(int x) {
    int d = x;
    return 10 / d;
}

int fp_shift_nonzero(void) {
    int d = 0;
    d = d + 1;
    return 10 / d;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "dbz.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewDivideByZeroDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if kept["fp_reassigned_nonzero"] {
		t.Errorf("fp_reassigned_nonzero (d reassigned to 1) should be suppressed, got %v", candidateNames(result))
	}
	if kept["fp_shift_nonzero"] {
		t.Errorf("fp_shift_nonzero (d = d + 1) should be suppressed, got %v", candidateNames(result))
	}
	if !kept["tp_zero"] {
		t.Errorf("tp_zero (d = 0) should be kept, got %v", candidateNames(result))
	}
	if !kept["tp_unknown"] {
		t.Errorf("tp_unknown (d = param) should be kept, got %v", candidateNames(result))
	}
}

// TestRangeFilter_IntOverflowConst pins the cross-assignment interval propagation
// for integer-overflow: `size_t n = 10; malloc(n * n)` is provably small and must
// be suppressed, while `malloc(n * n)` on a parameter stays.
func TestRangeFilter_IntOverflowConst(t *testing.T) {
	src := `#include <stdlib.h>

int fp_const_small(void) {
    size_t n = 10;
    void *p = malloc(n * n);
    return p != NULL;
}

int tp_param(int n) {
    void *p = malloc(n * n);
    return p != NULL;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "iof.c")
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

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if kept["fp_const_small"] {
		t.Errorf("fp_const_small (n = 10, malloc(n*n)) should be suppressed, got %v", candidateNames(result))
	}
	if !kept["tp_param"] {
		t.Errorf("tp_param (malloc(n*n) on a parameter) should be kept, got %v", candidateNames(result))
	}
}

// TestRangeFilter_IntOverflowLoopTerminates is the filter-path regression for the
// widening bug: an integer-overflow candidate function that ALSO contains a loop
// counter (`for (i=0; i<n; i++)`) must still converge. Before the widening fix the
// range analysis widened the loop counter one unit per back-edge pass and hung
// the whole plan. This is the end-to-end (detector → planner → filter →
// analyzeRanges) guard the engine-level TestAnalyzeRanges_TerminatesOnLoop alone
// would not catch.
func TestRangeFilter_IntOverflowLoopTerminates(t *testing.T) {
	src := `#include <stdlib.h>

int tp_loop_and_overflow(int n, int m) {
    char *p = (char *)malloc(n * m);
    if (!p) return -1;
    for (int i = 0; i < n; i++) {
        p[i] = 0;
    }
    free(p);
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "iof_loop.c")
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

	done := make(chan *PlanResult, 1)
	go func() {
		pl := NewPlanner(store, p, logger)
		res, err := pl.Plan(ctx, "integer-overflow")
		if err != nil {
			t.Errorf("plan: %v", err)
			done <- nil
			return
		}
		done <- res
	}()

	select {
	case result := <-done:
		if result == nil {
			return
		}
		kept := map[string]bool{}
		for _, c := range result.Candidates {
			kept[c.Target.Function] = true
		}
		if !kept["tp_loop_and_overflow"] {
			t.Errorf("tp_loop_and_overflow (malloc(n*m) on params, no guard) should be kept, got %v", candidateNames(result))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("integer-overflow plan did not terminate on a loop-counter function (widening regression via filter path)")
	}
}
