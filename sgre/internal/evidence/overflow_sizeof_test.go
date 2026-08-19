//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestIntegerOverflow_SizeofProduct(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc64_int_overflow_sizeof.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewIntegerOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "INTEGER_OVERFLOW")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	flagged := map[string]bool{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		flagged[fn.Name] = true
	}

	if !flagged["overflow_sizeof_alloc"] {
		t.Errorf("expected overflow_sizeof_alloc (n * sizeof(int)) to be flagged, got %v", flagged)
	}
	if !flagged["safe_var_var_alloc"] {
		t.Errorf("expected safe_var_var_alloc (m * n) to be flagged, got %v", flagged)
	}
	if flagged["safe_constant_alloc"] {
		t.Errorf("expected safe_constant_alloc (constant 256) NOT to be flagged, got %v", flagged)
	}
}

func TestBoundedCopyOverflow(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc65_bounded_copy_overflow.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	flagged := map[string]bool{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		flagged[fn.Name] = true
	}

	if !flagged["bounded_copy_overflow"] {
		t.Errorf("expected bounded_copy_overflow (strncpy dst[128] with n=256) to be flagged, got %v", flagged)
	}
	if flagged["safe_bounded_copy"] {
		t.Errorf("expected safe_bounded_copy (strncpy dst[256] with n=128) NOT to be flagged, got %v", flagged)
	}
	if flagged["bounded_copy_var_size"] {
		t.Errorf("expected bounded_copy_var_size (variable n, cannot prove) NOT to be flagged, got %v", flagged)
	}
}