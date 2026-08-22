package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestMacroFree_UAF pins that a freeing function-like macro (`#define my_free(p)
// free(p)`) is treated as a free site, so a later use is a use-after-free.
func TestMacroFree_UAF(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "macro_uaf.c")
	src := `#include <stdlib.h>

#define my_free(p) free(p)

struct Node { int value; };

int f(void) {
    struct Node *p = (struct Node *)malloc(sizeof(struct Node));
    my_free(p);
    return p->value;
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
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "USE_AFTER_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "p" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected use-after-free of p via freeing macro my_free, got no such event")
	}
}

// TestMacroFree_DoubleFree pins that a freeing macro used twice is a double-free.
func TestMacroFree_DoubleFree(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "macro_df.c")
	src := `#include <stdlib.h>

#define my_free(p) free(p)

struct Node { int value; };

int f(void) {
    struct Node *p = (struct Node *)malloc(sizeof(struct Node));
    my_free(p);
    my_free(p);
    return 0;
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
	NewDoubleFreeDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "DOUBLE_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "p" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected double-free of p via freeing macro my_free, got no such event")
	}
}

// TestMacroNull_NullSource pins that a free+null macro (`SAFE_FREE`) produces a
// DEFINITE null source for its argument, so a later deref is a null-deref.
func TestMacroNull_NullSource(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "macro_null.c")
	src := `#include <stdlib.h>

#define SAFE_FREE(p) do { free(p); p = NULL; } while (0)

struct Node { int value; };

int f(struct Node *p) {
    SAFE_FREE(p);
    return p->value;
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
	NewNullSourceDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Definite string `json:"definite"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "p" && props.Definite == "true" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a definite NULL_VALUE source for p via SAFE_FREE, got no such event")
	}
}

// TestMacroFree_MemoryLeak pins that a freeing macro releases its argument, so
// `p = malloc(); SAFE_FREE(p);` is NOT reported as a leak.
func TestMacroFree_MemoryLeak(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "macro_leak.c")
	src := `#include <stdlib.h>

#define SAFE_FREE(p) do { free(p); p = NULL; } while (0)

int f(void) {
    int *p = (int *)malloc(16);
    SAFE_FREE(p);
    return 0;
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	NewMemoryLeakDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "MEMORY_RELEASE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "p" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SAFE_FREE(p) to release p (no leak), got no MEMORY_RELEASE for p")
	}
}
