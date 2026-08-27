//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

const uafBofPreamble = `#include <stdlib.h>
#include <string.h>

typedef struct node { int value; struct node *next; char *msg; } node_t;

#define LIST_FOR_EACH(iter, head) \
    for ((iter) = (head); (iter) != NULL; (iter) = (iter)->next) {

#define LIST_FOR_EACH_END }
`

// TestUseAfterFree_MacroLoopUse pins the use-site recovery: a use of freed memory
// via a subscript inside a macro loop (`q->msg[0] = 1` after `free(q->msg)`) must
// be detected. Before extractFieldAccess/subscriptAccess recovered the base from
// the ERROR node, the use was missed.
func TestUseAfterFree_MacroLoopUse(t *testing.T) {
	src := uafBofPreamble + `
static int uaf_field(node_t *head) {
    node_t *q = (node_t *)malloc(sizeof(node_t));
    q->msg = (char *)malloc(10);
    node_t *iter;
    free(q->msg);
    LIST_FOR_EACH(iter, head)
        q->msg[0] = 1;
    LIST_FOR_EACH_END
    return 0;
}

int main(void) { return uaf_field((node_t *)0); }
`
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "uaf_macro.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "use-after-free")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	c := candidateForFunc(t, result, "uaf_field")
	if c == nil {
		t.Fatalf("expected a use-after-free candidate in uaf_field(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
}

// TestBufferOverflow_MacroLoopOOBWrite pins the array-OOB-write recovery: a
// constant-index write past a known array size inside a macro loop (`arr[10] = 1`
// on `int arr[4]`) must be detected. Before subscriptBaseIndex recovered the
// array name + index from the ERROR node, the OOB write was missed.
func TestBufferOverflow_MacroLoopOOBWrite(t *testing.T) {
	src := uafBofPreamble + `
static int bof_oob_write(node_t *head) {
    int arr[4];
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        arr[10] = 1;
    LIST_FOR_EACH_END
    return 0;
}

int main(void) { return bof_oob_write((node_t *)0); }
`
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "bof_macro.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "buffer-overflow")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if c := candidateForFunc(t, result, "bof_oob_write"); c == nil {
		t.Fatalf("expected a buffer-overflow candidate in bof_oob_write(), got: %s", candidateNames(result))
	}
}
