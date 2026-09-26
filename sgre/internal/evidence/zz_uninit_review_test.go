//go:build !nosqlite

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

func uninitHeapOrigins(t *testing.T, src string) map[string]int {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "u.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewUninitVariableDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "VALUE_USE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	out := map[string]int{}
	for _, e := range events {
		var props struct {
			Origin string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		fn, _ := store.GetFunctionByID(ctx, e.EntityID)
		if fn == nil {
			continue
		}
		out[fn.Name+"|"+props.Origin]++
	}
	return out
}

// UN-05: a subscript read `p[0]` of a malloc'd block is an uninitialized read and
// must be flagged (the previous scan only covered `*p` / `p->f`).
func TestUninitReview_HeapSubscriptRead(t *testing.T) {
	src := `#include <stdlib.h>
int f(int n) {
    int *p = malloc(n * sizeof(int));
    return p[0];
}
`
	got := uninitHeapOrigins(t, src)
	if got["f|heap_uninit"] == 0 {
		t.Errorf("f (malloc then p[0]) should be flagged heap_uninit, got %v", got)
	}
}

// UN-11: calloc zero-initializes the block, so `*p` / `p->f` after calloc must NOT
// be flagged heap_uninit.
func TestUninitReview_CallocZeroInit(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct S { int len; } S;
int f(void) {
    int *p = calloc(1, sizeof(int));
    return *p;
}
int g(void) {
    S *s = calloc(1, sizeof(S));
    return s->len;
}
`
	got := uninitHeapOrigins(t, src)
	if got["f|heap_uninit"] != 0 || got["g|heap_uninit"] != 0 {
		t.Errorf("calloc blocks must NOT be flagged heap_uninit, got %v", got)
	}
}

// UN-14: memset with a sizeof size (`sizeof(struct S)`, not just `sizeof(*p)`)
// fully initializes the block, so a later field read must not be flagged.
func TestUninitReview_MemsetTypeName(t *testing.T) {
	src := `#include <stdlib.h>
#include <string.h>
typedef struct S { int len; } S;
int f(void) {
    S *p = malloc(sizeof(S));
    memset(p, 0, sizeof(struct S));
    return p->len;
}
`
	got := uninitHeapOrigins(t, src)
	if got["f|heap_uninit"] != 0 {
		t.Errorf("memset(p, 0, sizeof(struct S)) fully initializes the block, got %v", got)
	}
}

// UN-07: a nested member read (`p->inner->len` on a malloc'd struct, `s.inner.len`
// on a stack struct) resolves to the base variable, so it is an uninitialized read.
// The previous scan keyed the base by the first child (`p->inner`), which never
// matched the tracked malloc/struct variable (`p` / `s`) — a systematic miss.
func TestUninitReview_NestedField(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct Inner { int len; } Inner;
typedef struct S { Inner inner; } S;
int f(void) {
    S *p = malloc(sizeof(S));
    return p->inner->len;
}
int g(void) {
    S s;
    return s.inner.len;
}
`
	got := uninitHeapOrigins(t, src)
	if got["f|heap_uninit"] == 0 {
		t.Errorf("f (malloc then p->inner->len) should be flagged heap_uninit, got %v", got)
	}
	if got["g|struct_partial_uninit"] == 0 {
		t.Errorf("g (uninit struct then s.inner.len) should be flagged struct_partial_uninit, got %v", got)
	}
}
