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

// bofLeakFixture pins the buffer-overflow and memory-leak cases that ARE
// detected, so a regression cannot silently drop them.
//
// Known recall gaps (deliberate tradeoffs / future features, NOT asserted):
//   - bof_loop_write (`buf[i] = src[i]` with a variable loop bound): the
//     buffer-overflow detector intentionally does not flag non-constant
//     subscripts without bounds-check dataflow (flagging them produced ~17
//     benchmark false positives).
//   - leak_reassign (`p = malloc(); p = malloc(); free(p)`): the first block
//     leaks, but detecting it needs flow-sensitive reassignment tracking.
//   - leak_cond_path (`if (flag) return -1; free(p)` in a flat function): the
//     memory-leak detector's coarse CFG degenerates to a conservative "released"
//     fallback for flat functions; a proper fix needs the statement CFG plus
//     ownership-transfer (return/global-store) recognition.
const bofLeakFixture = `#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int bof_strcpy(char *src) {
    char buf[10];
    strcpy(buf, src);
    return buf[0];
}
int bof_memcpy(char *src, int n) {
    char buf[10];
    memcpy(buf, src, n);
    return buf[0];
}
int bof_sprintf(char *user) {
    char buf[10];
    sprintf(buf, "%s", user);
    return buf[0];
}
int bof_strcat(char *src) {
    char buf[10] = "x";
    strcat(buf, src);
    return buf[0];
}
int bof_loop_const(void) {
    char buf[10];
    for (int i = 0; i <= 10; i++) buf[i] = 0;
    return buf[0];
}
int leak_no_free(void) {
    char *p = (char *)malloc(100);
    return p[0];
}
int leak_cond_path(int flag) {
    char *p = (char *)malloc(100);
    if (flag) return -1;
    free(p);
    return 0;
}
int g_sink;
int leak_global_escaped(void) {
    g_sink = (int)(size_t)malloc(64);
    return 0;
}
`

func TestRecall_BufferOverflowMemoryLeak(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "bofleak.c")
	if err := os.WriteFile(path, []byte(bofLeakFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)

	expected := map[string][]string{
		"buffer-overflow": {"bof_strcpy", "bof_memcpy", "bof_sprintf", "bof_strcat", "bof_loop_const"},
		"memory-leak":     {"leak_no_free", "leak_cond_path"},
	}

	for _, vt := range []string{"buffer-overflow", "memory-leak"} {
		pl := NewPlanner(store, p, logger)
		res, err := pl.Plan(ctx, vt)
		if err != nil {
			t.Fatalf("%s plan: %v", vt, err)
		}
		caught := map[string]bool{}
		for _, c := range res.Candidates {
			caught[c.Target.Function] = true
		}
		for _, fn := range expected[vt] {
			if !caught[fn] {
				t.Errorf("%s: expected true positive %q to be kept (recall), got candidates %v", vt, fn, candidateNames(res))
			}
		}
		if vt == "memory-leak" && caught["leak_global_escaped"] {
			t.Errorf("memory-leak: leak_global_escaped (malloc stored to a global) should NOT be reported as a leak, got %v", candidateNames(res))
		}
	}
}
