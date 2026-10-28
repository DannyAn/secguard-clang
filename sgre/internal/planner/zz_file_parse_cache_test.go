//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestFileParseCacheParamsEquivalence locks in the behavior of the cached
// defFor/paramsFor/paramListFor/voidPtrParamsFor lookups that replaced the
// per-function whole-file FindAll("function_definition") in paramsOf /
// paramListOf / voidPtrParamsOf. The refactor changed WHERE the function
// definition is resolved (a per-file map keyed by start line instead of a
// re-walk), not the answer, so the cache must return the same parameters the
// old whole-file scan did — across the declarator shapes that historically
// needed unwrapping (pointer-returning and nested-pointer functions) and the
// void*/const void* contract shape that must exclude function-pointer params.
func TestFileParseCacheParamsEquivalence(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "params.c")
	src := `int plain(int a, const char *b) { return a; }

int *ptr_return(char *p, int n) { (void)p; (void)n; return 0; }

char **nested_ptr(const char **pp, int n) { (void)pp; (void)n; return 0; }

void opaque(void *v, const void *cv, int x) { (void)v; (void)cv; (void)x; }

void variadic(const char *fmt, ...) { (void)fmt; }

void funcptr(void (*cb)(int), int n) { (void)cb; (void)n; }
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, log.Default())
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}

	files, err := store.ListFiles(ctx)
	if err != nil || len(files) == 0 {
		t.Fatalf("list files: %v (files=%d)", err, len(files))
	}
	file := files[0]
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		t.Fatalf("list functions: %v", err)
	}
	fnByName := map[string]*db.Function{}
	for _, fn := range funcs {
		fnByName[fn.Name] = fn
	}

	cache := newFileParseCache(p)

	type want struct {
		params     map[string]int
		list       []string
		voidParams map[string]bool
	}
	cases := map[string]want{
		"plain": {
			params:     map[string]int{"a": 0, "b": 1},
			list:       []string{"a", "b"},
			voidParams: map[string]bool{},
		},
		"ptr_return": {
			params:     map[string]int{"p": 0, "n": 1},
			list:       []string{"p", "n"},
			voidParams: map[string]bool{},
		},
		"nested_ptr": {
			params:     map[string]int{"pp": 0, "n": 1},
			list:       []string{"pp", "n"},
			voidParams: map[string]bool{},
		},
		"opaque": {
			params:     map[string]int{"v": 0, "cv": 1, "x": 2},
			list:       []string{"v", "cv", "x"},
			voidParams: map[string]bool{"v": true, "cv": true},
		},
		"variadic": {
			params:     map[string]int{"fmt": 0},
			list:       []string{"fmt"},
			voidParams: map[string]bool{},
		},
		"funcptr": {
			params:     map[string]int{"cb": 0, "n": 1},
			list:       []string{"cb", "n"},
			voidParams: map[string]bool{},
		},
	}

	for name, w := range cases {
		fn := fnByName[name]
		if fn == nil {
			t.Fatalf("indexed function %q missing", name)
		}
		if got := cache.paramsFor(file, fn); !reflect.DeepEqual(got, w.params) {
			t.Errorf("%s: paramsFor = %v, want %v", name, got, w.params)
		}
		if got := cache.paramListFor(file, fn); !reflect.DeepEqual(got, w.list) {
			t.Errorf("%s: paramListFor = %v, want %v", name, got, w.list)
		}
		if got := cache.voidPtrParamsFor(file, fn); !reflect.DeepEqual(got, w.voidParams) {
			t.Errorf("%s: voidPtrParamsFor = %v, want %v", name, got, w.voidParams)
		}
		// defFor must return the actual function_definition node (not the zero
		// node), keyed by the same start line cache.get uses for the body.
		def := cache.defFor(file, fn)
		if def.Kind() != "function_definition" {
			t.Errorf("%s: defFor kind = %q, want function_definition", name, def.Kind())
		}
	}
}
