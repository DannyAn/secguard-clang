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

// runPathTraversalWithGuards indexes src with a config declaring
// idm_file_path_is_valid as a path-traversal guard function, runs the detector,
// and returns the store.
func runPathTraversalWithGuards(t *testing.T, src string) db.Store {
	t.Helper()
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(tomlPath, []byte(`[guards.path_traversal]
names = ["idm_file_path_is_valid"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(tomlPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

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
	return store
}

func pathTraversalFuncs(t *testing.T, store db.Store) map[string]int {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "PATH_TRAVERSAL")
	if err != nil {
		t.Fatalf("list PATH_TRAVERSAL: %v", err)
	}
	byFunc := make(map[string]int)
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		byFunc[fn.Name]++
	}
	return byFunc
}

// TestPathTraversal_GuardFunctionSuppresses pins the config-driven guard
// function: when [guards.path_traversal] names a validation function called
// with the same path argument BEFORE the sink, the candidate is suppressed. A
// guard called after the sink, with a different argument, or in another function
// proves nothing and must not suppress.
func TestPathTraversal_GuardFunctionSuppresses(t *testing.T) {
	store := runPathTraversalWithGuards(t, `#include <stdio.h>

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
`)
	byFunc := pathTraversalFuncs(t, store)
	for _, name := range []string{"guarded_open", "guarded_open_cast", "guard_other_function"} {
		if byFunc[name] != 0 {
			t.Errorf("%s: guard precedes the sink with the same argument, expected no event, got %d", name, byFunc[name])
		}
	}
	for _, name := range []string{"guard_after_sink", "unguarded_open", "guard_other_arg"} {
		if byFunc[name] != 1 {
			t.Errorf("%s: expected exactly 1 PATH_TRAVERSAL event, got %d", name, byFunc[name])
		}
	}
}

// TestPathTraversal_GuardCallForms pins that the guard rule keys on the CALL
// (which function, which argument, which line), never on the shape of the
// surrounding `if` — every form below is semantically a guard and must
// suppress. The construction case at the end is the documented boundary: a path
// BUILT by snprintf is not the guarded value itself, so it is still reported
// (deciding that case needs the base directory's provenance, not a name list).
func TestPathTraversal_GuardCallForms(t *testing.T) {
	store := runPathTraversalWithGuards(t, `#include <stdio.h>
#include <assert.h>

int idm_file_path_is_valid(const char *filename);

void form_negated_early_return(const char *p) {
    if (!idm_file_path_is_valid(p)) return;
    FILE *f = fopen(p, "r");
    if (f) fclose(f);
}

void form_compare_goto(const char *p) {
    if (idm_file_path_is_valid(p) == 0) goto err;
    {
        FILE *f = fopen(p, "r");
        if (f) fclose(f);
    }
    return;
err:
    return;
}

void form_result_var(const char *p) {
    int ok = idm_file_path_is_valid(p);
    if (!ok) return;
    FILE *f = fopen(p, "r");
    if (f) fclose(f);
}

void form_assert(const char *p) {
    assert(idm_file_path_is_valid(p));
    FILE *f = fopen(p, "r");
    if (f) fclose(f);
}

void form_combined(const char *p, const char *q) {
    if (!idm_file_path_is_valid(p) || !idm_file_path_is_valid(q)) return;
    FILE *f = fopen(q, "r");
    if (f) fclose(f);
}

void form_if_else(const char *p) {
    if (idm_file_path_is_valid(p) != 0) {
        FILE *f = fopen(p, "r");
        if (f) fclose(f);
    } else {
        return;
    }
}

void form_constructed_path(const char *name) {
    char path[256];
    if (!idm_file_path_is_valid(name)) return;
    snprintf(path, sizeof(path), "%s/%s", "/flash", name);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}
`)
	byFunc := pathTraversalFuncs(t, store)
	for _, name := range []string{
		"form_negated_early_return",
		"form_compare_goto",
		"form_result_var",
		"form_assert",
		"form_combined",
		"form_if_else",
	} {
		if byFunc[name] != 0 {
			t.Errorf("%s: guard call precedes the sink, expected no event regardless of the if-shape, got %d", name, byFunc[name])
		}
	}
	if byFunc["form_constructed_path"] != 1 {
		t.Errorf("form_constructed_path: the sink argument is a buffer built by snprintf, not the guarded value, expected 1 event (documented boundary), got %d", byFunc["form_constructed_path"])
	}
}
