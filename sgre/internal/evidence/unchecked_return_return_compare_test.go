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

// TestUncheckedReturn_ReturnCompareConsumed pins the return-comparison rule: a
// stored call result that is handed to the caller as a comparison predicate
// (`return f != 0;`) IS consumed — the failure sentinel decides the function's
// own return value — so it must not be emitted as an unchecked return. A stored
// result with no such consumption still reports.
func TestUncheckedReturn_ReturnCompareConsumed(t *testing.T) {
	src := `#include <stdio.h>

int compared_on_return(const char *p) {
    FILE *f = fopen(p, "r");
    return f != 0;
}

int compared_on_return_paren(const char *p) {
    FILE *f = fopen(p, "r");
    return (f == NULL) ? -1 : 0;
}

int compared_on_return_relational(const char *p) {
    FILE *f = fopen(p, "r");
    return f == NULL;
}

int stored_then_used(const char *p) {
    FILE *f = fopen(p, "r");
    fclose(f);
    return 0;
}

int bare_return_is_passthrough_domain(const char *p) {
    FILE *f = fopen(p, "r");
    return f;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "return_compare.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	if _, err := NewUncheckedReturnDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	byFunc := map[string]int{}
	events, err := store.ListEventsByType(ctx, "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list UNCHECKED_RETURN: %v", err)
	}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		byFunc[fn.Name]++
	}

	for _, name := range []string{"compared_on_return", "compared_on_return_paren", "compared_on_return_relational", "bare_return_is_passthrough_domain"} {
		if byFunc[name] != 0 {
			t.Errorf("%s: a result consumed by a return comparison is checked, got %d event(s)", name, byFunc[name])
		}
	}
	if byFunc["stored_then_used"] != 1 {
		t.Errorf("stored_then_used: expected exactly 1 UNCHECKED_RETURN event (the stored result is used but never checked), got %d", byFunc["stored_then_used"])
	}
}
