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

func TestUncheckedReturn_SwitchCheck(t *testing.T) {
	src := `#include <stdlib.h>

int fp_switch_check(void) {
    int ret = read(0, NULL, 0);
    switch (ret) {
    case 0: return 0;
    case -1: return -1;
    default: return ret;
    }
}

int tp_unchecked(void) {
    read(0, NULL, 0);
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "switch_check.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	detector := NewUncheckedReturnDetector(store, p, logger)
	result, err := detector.Detect(ctx)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	if result.EventsCreated != 1 {
		t.Errorf("expected 1 UNCHECKED_RETURN event (tp_unchecked only), got %d", result.EventsCreated)
	}
}

func TestUncheckedReturn_BitwiseCheck(t *testing.T) {
	src := `#include <stdlib.h>

#define ERROR_MASK 0xff

int fp_bitwise_check(void) {
    int ret = read(0, NULL, 0);
    if (ret & ERROR_MASK) return -1;
    return ret;
}

int tp_unchecked(void) {
    read(0, NULL, 0);
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "bitwise_check.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	detector := NewUncheckedReturnDetector(store, p, logger)
	result, err := detector.Detect(ctx)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	if result.EventsCreated != 1 {
		t.Errorf("expected 1 UNCHECKED_RETURN event (tp_unchecked only), got %d", result.EventsCreated)
	}
}
