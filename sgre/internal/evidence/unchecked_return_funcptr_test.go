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

// TestUncheckedReturn_FuncPtrNotSyscall pins the function-pointer distinction:
// a local variable named `read` declared as a function pointer shadows the
// POSIX read() syscall. The detector must NOT flag the function-pointer call,
// while a genuine POSIX read() with an unchecked return is still flagged.
func TestUncheckedReturn_FuncPtrNotSyscall(t *testing.T) {
	dir := t.TempDir()
	src := `#include <unistd.h>

void func_ptr_read(void) {
    int (*read)(void *, size_t, void *);
    char buf[256];
    read(buf, 100, 0);
}

void real_read(int fd) {
    char buf[256];
    read(fd, buf, 100);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "func_ptr.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewUncheckedReturnDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list UNCHECKED_RETURN: %v", err)
	}
	byFunc := make(map[string]int)
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		byFunc[fn.Name]++
	}
	if byFunc["func_ptr_read"] > 0 {
		t.Errorf("func_ptr_read should have NO unchecked-return events (read is a function pointer), got %d", byFunc["func_ptr_read"])
	}
	if byFunc["real_read"] == 0 {
		t.Errorf("real_read should have an unchecked-return event (POSIX read() return not checked)")
	}
}
