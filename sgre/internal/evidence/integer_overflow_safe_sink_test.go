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
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestIntegerOverflow_UnsignedSubSafeFunctionSink pins the safe-function
// suppression: an unsigned subtraction passed to a safe-function-family API
// (sprintf_s) is NOT flagged, because the safe function bounds-checks its
// size argument and returns an error instead of overflowing. The suppression is
// limited to the Annex K `_s` family: a subtraction passed to malloc, to a
// bounded-copy API whose size argument is consumed unchecked (strlcpy), or to a
// bind API whose length argument is consumed unchecked (sqlite3_bind_blob) is
// still a real defect and must be flagged.
func TestIntegerOverflow_UnsignedSubSafeFunctionSink(t *testing.T) {
	dir := t.TempDir()
	src := `#include <stdio.h>
#include <stdlib.h>

int sprintf_s(char *dest, size_t dest_sz, const char *fmt, ...);
size_t strlcpy(char *dst, const char *src, size_t size);
int sqlite3_bind_blob(void *stmt, int idx, const void *blob, int n, void *dtor);

void safe_underflow_to_sprintf_s(char *buf, size_t size, size_t offset, const char *ip) {
    int ret = sprintf_s(buf + offset, size - offset, "%s", ip);
    if (ret < 0) return;
}

void unsafe_underflow_to_malloc(size_t size, size_t offset) {
    void *p = malloc(size - offset);
    free(p);
}

void unsafe_underflow_to_strlcpy(char *dst, const char *src, size_t size, size_t offset) {
    strlcpy(dst, src, size - offset);
}

void unsafe_underflow_to_bind(size_t size, size_t offset, void *stmt, const void *blob) {
    sqlite3_bind_blob(stmt, 1, blob, size - offset, 0);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "safe_sink.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewIntegerOverflowDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "INTEGER_OVERFLOW")
	if err != nil {
		t.Fatalf("list INTEGER_OVERFLOW: %v", err)
	}
	byFunc := make(map[string][]string)
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		byFunc[fn.Name] = append(byFunc[fn.Name], props.Category)
	}
	if cats, ok := byFunc["safe_underflow_to_sprintf_s"]; ok {
		t.Errorf("safe_underflow_to_sprintf_s should have NO overflow events (sprintf_s is safe), got %v", cats)
	}
	for _, name := range []string{
		"unsafe_underflow_to_malloc",
		"unsafe_underflow_to_strlcpy",
		"unsafe_underflow_to_bind",
	} {
		if _, ok := byFunc[name]; !ok {
			t.Errorf("%s should have an unsigned_sub_underflow event", name)
		}
	}
}
