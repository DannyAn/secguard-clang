//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// runPathTraversal indexes src into a fresh store and runs the detector.
func runPathTraversal(t *testing.T, src string) db.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "const_path.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewPathTraversalDetector(store, parser.NewParser(), logger).Detect(ctx); err != nil {
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

// TestPathTraversal_StringConstants pins the compile-time-constant suppression:
// a sink whose path argument is a string literal, expands from a string-valued
// macro, names a `static const char` object, or is a local buffer assembled only
// from those is not attacker-influenceable and must not be reported. Anything
// that can be influenced at run time must still be reported — including a macro
// that concatenates a constant with an unknown name, a mutable static array, a
// reassigned `static const char *`, and a buffer built with a run-time component.
func TestPathTraversal_StringConstants(t *testing.T) {
	store := runPathTraversal(t, `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DIR "/var/lib/idm"
#define DB_PATH DIR "/db"
#define LOG_PATH DIR "/log"
#define TAINTED_JOIN DIR user_component

static const char g_arr[] = "/tmp/arr";
static const char *g_ptr = "/tmp/ptr";
static const char *g_reassigned = "/tmp/orig";
static char g_mutable[] = "/tmp/mutable";
const char *g_nonstatic = "/tmp/nonstatic";

void literal_sink(void) {
    FILE *f = fopen("/tmp/literal", "r");
    if (f) fclose(f);
}

void macro_sink(void) {
    FILE *f = fopen(DB_PATH, "r");
    if (f) fclose(f);
}

void macro_concat_sink(void) {
    FILE *f = fopen(LOG_PATH, "r");
    if (f) fclose(f);
}

void static_array_sink(void) {
    FILE *f = fopen(g_arr, "r");
    if (f) fclose(f);
}

void static_ptr_sink(void) {
    FILE *f = fopen(g_ptr, "r");
    if (f) fclose(f);
}

void built_from_macro(void) {
    char path[256];
    snprintf(path, sizeof(path), "%s", DB_PATH);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void built_by_strcpy(void) {
    char path[256];
    strcpy(path, DB_PATH);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void runtime_param(const char *user_path) {
    FILE *f = fopen(user_path, "r");
    if (f) fclose(f);
}

void tainted_macro_sink(void) {
    FILE *f = fopen(TAINTED_JOIN, "r");
    if (f) fclose(f);
}

void mutable_array_sink(void) {
    FILE *f = fopen(g_mutable, "r");
    if (f) fclose(f);
}

void reassigned_ptr_sink(void) {
    g_reassigned = getenv("PATH_OVERRIDE");
    FILE *f = fopen(g_reassigned, "r");
    if (f) fclose(f);
}

void nonstatic_ptr_sink(void) {
    FILE *f = fopen(g_nonstatic, "r");
    if (f) fclose(f);
}

void built_with_runtime_part(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", DIR, name);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}
`)
	byFunc := pathTraversalFuncs(t, store)

	for _, name := range []string{
		"literal_sink",
		"macro_sink",
		"macro_concat_sink",
		"static_array_sink",
		"static_ptr_sink",
		"built_from_macro",
		"built_by_strcpy",
	} {
		if byFunc[name] != 0 {
			t.Errorf("%s: path is a compile-time constant, expected no event, got %d", name, byFunc[name])
		}
	}
	for _, name := range []string{
		"runtime_param",
		"tainted_macro_sink",
		"mutable_array_sink",
		"reassigned_ptr_sink",
		"nonstatic_ptr_sink",
		"built_with_runtime_part",
	} {
		if byFunc[name] != 1 {
			t.Errorf("%s: path can be influenced at run time, expected exactly 1 event, got %d", name, byFunc[name])
		}
	}
}
