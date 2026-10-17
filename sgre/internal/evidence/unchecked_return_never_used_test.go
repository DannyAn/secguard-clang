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

// TestUncheckedReturn_NeverUsedStore pins the never-observably-used rule for a
// stored allocation result: a NULL-safe deallocation, a sizeof operand (an
// unevaluated compile-time query), a dead store, and a rebinding that kills
// the old value all leave the failure unobservable, so no unchecked-return
// event is emitted. A dereference (including one after free) and a global
// target (whose uses live in other functions) still report.
func TestUncheckedReturn_NeverUsedStore(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct Node { int value; } Node;
static Node g_fallback;
static void *g_buf;

int sizeof_operand_free_only(void) {
    Node *node = (Node *)malloc(sizeof(Node));
    int a = sizeof(node->value);
    int b = sizeof(node[0]);
    free(node);
    return a + b;
}

int dead_store_never_used(void) {
    int *p = (int *)malloc(16);
    return 0;
}

int overwritten_before_use(void) {
    int *p = (int *)malloc(16);
    p = (int *)malloc(32);
    free(p);
    return 0;
}

int freed_then_rebound(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    free(p);
    p = &g_fallback;
    return p->value;
}

int copied_then_rebound(void) {
    Node *a = (Node *)malloc(sizeof(Node));
    Node *b = &g_fallback;
    free(a);
    a = b;
    return a->value;
}

void free_param(char *p) {
    p = (char *)malloc(16);
    free(p);
}

int deref_disqualifies(void) {
    int *p = (int *)malloc(16);
    p[0] = 1;
    free(p);
    return 0;
}

int use_after_free_disqualifies(void) {
    Node *p = (Node *)malloc(sizeof(Node));
    free(p);
    return p->value;
}

void store_global(void) {
    g_buf = (void *)malloc(16);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "never_used.c")
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

	for _, name := range []string{
		"sizeof_operand_free_only",
		"dead_store_never_used",
		"overwritten_before_use",
		"freed_then_rebound",
		"copied_then_rebound",
		"free_param",
	} {
		if byFunc[name] != 0 {
			t.Errorf("%s: a store never observably used has no unchecked-return defect, got %d event(s)", name, byFunc[name])
		}
	}
	for _, name := range []string{"deref_disqualifies", "use_after_free_disqualifies", "store_global"} {
		if byFunc[name] != 1 {
			t.Errorf("%s: expected exactly 1 UNCHECKED_RETURN event, got %d", name, byFunc[name])
		}
	}
}
