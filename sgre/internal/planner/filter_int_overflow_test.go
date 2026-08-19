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

func TestIntOverflowGuardFilter(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "iof.c")
	src := `#include <stdlib.h>

int get_count(void) { return 0; }
int get_size(void) { return 0; }

void guarded(void) {
    int n = get_count();
    int size = get_size();
    if (n < 100) {
        if (size < 100) {
            char *buf = malloc(n * size);
            (void)buf;
        }
    }
}

void unguarded(void) {
    int n = get_count();
    int size = get_size();
    char *buf = malloc(n * size);
    (void)buf;
}
`
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

	if kept["guarded"] {
		t.Errorf("guarded (n<100 && size<100) should be suppressed, got %v", candidateNames(result))
	}
	if !kept["unguarded"] {
		t.Errorf("unguarded (unbounded n*size) should be kept, got %v", candidateNames(result))
	}
}

// TestIntOverflowGuardFilter_AddConst locks in the range-domain extension: the
// new size_add_overflow / size_mul_const_overflow patterns are also dropped when
// the variable operand is guarded to a small constant (`if (n < 100)`), since
// n + const and n * const then cannot overflow.
func TestIntOverflowGuardFilter_AddConst(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "iof_add.c")
	src := `#include <stdlib.h>

void guarded_add(size_t n) {
    if (n < 100) {
        char *buf = malloc(n + 1);
        (void)buf;
    }
}

void guarded_mul(size_t n) {
    if (n < 100) {
        char *buf = malloc(n * 4);
        (void)buf;
    }
}

void unguarded_add(size_t n) {
    char *buf = malloc(n + 1);
    (void)buf;
}
`
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

	if kept["guarded_add"] {
		t.Errorf("guarded_add (n<100, malloc(n+1)) should be suppressed, got %v", candidateNames(result))
	}
	if kept["guarded_mul"] {
		t.Errorf("guarded_mul (n<100, malloc(n*4)) should be suppressed, got %v", candidateNames(result))
	}
	if !kept["unguarded_add"] {
		t.Errorf("unguarded_add (unbounded malloc(n+1)) should be kept, got %v", candidateNames(result))
	}
}
