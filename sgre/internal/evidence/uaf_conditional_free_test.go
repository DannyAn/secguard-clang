//go:build !nosqlite

package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestUAF_ConditionalFreeInCallee_NoUAF(t *testing.T) {
	src := `#include <stdlib.h>

struct node {
    char *data;
};

void maybe_free(struct node *n) {
    if (n->data != NULL) free(n->data);
}

int fp_conditional_cleanup(struct node *n) {
    maybe_free(n);
    return n->data[0];
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "cond_free.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	detector := NewUseAfterFreeDetector(store, p, logger)
	result, err := detector.Detect(ctx)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if result.EventsCreated > 0 {
		t.Errorf("expected 0 UAF events for conditional free in callee, got %d", result.EventsCreated)
	}
}

func TestUAF_UnconditionalFreeInCallee_StillDetected(t *testing.T) {
	src := `#include <stdlib.h>

struct node {
    char *data;
};

void always_free(struct node *n) {
    free(n->data);
}

int tp_unconditional_cleanup(struct node *n) {
    always_free(n);
    return n->data[0];
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "uncond_free.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	detector := NewUseAfterFreeDetector(store, p, logger)
	result, err := detector.Detect(ctx)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if result.EventsCreated == 0 {
		t.Errorf("expected UAF event for unconditional free in callee, got 0")
	}
}
