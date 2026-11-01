//go:build !nosqlite

package graph

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestFuncPtrWrite_IndirectCallResolved pins GAP-02: `ops->open = my_open` and
// `.open = my_open` resolve `ops->open(p)` to a real CALL edge to my_open (the
// pre-GAP-02 behavior was an external edge, so my_open was unreachable).
func TestFuncPtrWrite_IndirectCallResolved(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "tc177_func_ptr.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	if err := NewFuncPtrWriteBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("func ptr writes: %v", err)
	}
	writes, err := store.ListFuncPtrWrites(ctx)
	if err != nil {
		t.Fatalf("list func ptr writes: %v", err)
	}
	if len(writes) < 2 {
		t.Fatalf("expected >= 2 func-ptr writes (assign + initializer), got %d", len(writes))
	}

	if _, err := NewCallGraphBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("call graph: %v", err)
	}

	// my_open must now have an in-tree CALLER (use_ops and use_initializer), i.e.
	// the indirect call resolved to a real edge instead of an external one.
	funcs, _ := store.ListFunctions(ctx)
	nodeByFunc := map[int64]int64{}
	nodes, _ := store.ListGraphNodesByEntityType(ctx, "function")
	for _, n := range nodes {
		nodeByFunc[n.EntityID] = n.ID
	}
	var myOpenNode, useOpsNode, useInitNode int64
	for _, f := range funcs {
		switch f.Name {
		case "my_open":
			myOpenNode = nodeByFunc[f.ID]
		case "use_ops":
			useOpsNode = nodeByFunc[f.ID]
		case "use_initializer":
			useInitNode = nodeByFunc[f.ID]
		}
	}
	edges, _ := store.ListGraphEdgesByType(ctx, "CALL")
	callers := map[int64]bool{}
	for _, e := range edges {
		if e.DstID == myOpenNode {
			callers[e.SrcID] = true
		}
	}
	if !callers[useOpsNode] {
		t.Errorf("use_ops -> my_open CALL edge missing (indirect call unresolved)")
	}
	if !callers[useInitNode] {
		t.Errorf("use_initializer -> my_open CALL edge missing (initializer-pair unresolved)")
	}
}
