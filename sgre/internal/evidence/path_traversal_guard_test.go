//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestPathTraversal_GuardFunctionSuppresses pins the config-driven guard
// function: when [guards.path_traversal] names a validation function called
// with the same path argument BEFORE the sink, the candidate is suppressed. A
// guard called after the sink, with a different argument, or in another function
// proves nothing and must not suppress.
func TestPathTraversal_GuardFunctionSuppresses(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(tomlPath, []byte(`[guards.path_traversal]
names = ["idm_file_path_is_valid"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(tomlPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

	src := `#include <stdio.h>

int idm_file_path_is_valid(const char *filename);

void guarded_open(const char *path) {
    if (!idm_file_path_is_valid(path)) {
        return;
    }
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void guarded_open_cast(const char *path) {
    if (!idm_file_path_is_valid(path)) {
        return;
    }
    FILE *f = fopen((const char *)path, "r");
    if (f) fclose(f);
}

void guard_after_sink(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
    (void)idm_file_path_is_valid(path);
}

void unguarded_open(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void guard_other_arg(const char *path, const char *other) {
    if (!idm_file_path_is_valid(other)) {
        return;
    }
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void guard_other_function(const char *path) {
    if (!idm_file_path_is_valid(path)) {
        return;
    }
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "guard_test.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewPathTraversalDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "PATH_TRAVERSAL")
	if err != nil {
		t.Fatalf("list PATH_TRAVERSAL: %v", err)
	}
	// guarded_open / guarded_open_cast / guard_other_function are suppressed;
	// guard_after_sink, unguarded_open and guard_other_arg are reported.
	if len(events) != 3 {
		var funcs []string
		for _, e := range events {
			if fn, err := store.GetFunctionByID(ctx, e.EntityID); err == nil && fn != nil {
				funcs = append(funcs, fn.Name)
			}
		}
		t.Fatalf("expected 3 PATH_TRAVERSAL events (guard_after_sink, unguarded_open, guard_other_arg), got %d in %v", len(events), funcs)
	}
}
