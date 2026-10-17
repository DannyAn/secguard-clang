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

// TestUncheckedReturn_FreeOnlyIsNotADefect pins the NULL-safe-deallocation rule:
// an allocation whose only consumer is free() is not a CWE-252 defect (free(NULL)
// is a defined no-op), so it must not reach the candidate index — let alone the
// auto-confirmed tier. The rule is deliberately narrow: a dereference or a
// non-free deallocator (which may dereference its argument) still reports.
func TestUncheckedReturn_FreeOnlyIsNotADefect(t *testing.T) {
	src := `#include <stdlib.h>

void only_freed(int n) {
    char **p = malloc(n * sizeof(p));
    free(p);
}

void freed_through_parentheses(int n) {
    char *p = malloc(n);
    free((void *)p);
}

void deref_before_free(int n) {
    int *p = malloc(n);
    p[0] = 1;
    free(p);
}

void non_null_safe_deallocator(int n) {
    char *p = malloc(n);
    wrapper_destroy(p);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "free_only.c")
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

	for _, name := range []string{"only_freed", "freed_through_parentheses"} {
		if byFunc[name] != 0 {
			t.Errorf("%s: a pointer only passed to free() has no unchecked-return defect, got %d event(s)", name, byFunc[name])
		}
	}
	for _, name := range []string{"deref_before_free", "non_null_safe_deallocator"} {
		if byFunc[name] != 1 {
			t.Errorf("%s: expected exactly 1 UNCHECKED_RETURN event, got %d", name, byFunc[name])
		}
	}
}
