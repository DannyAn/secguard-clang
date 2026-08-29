//go:build !nosqlite

package planner

import (
	"context"
	"io"
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

// TestNullDeref_DerefArgCallKillsNull pins the implicit non-null kill: a library
// function that unconditionally dereferences a by-value pointer argument
// (memset_s/memcpy write through their first args) proves that argument is
// non-null on the continuation, because reaching the next statement means the
// call did not fault. `head = get_head(); ...; memset_s(head, ...); ...;
// head->f` must therefore not be a null-deref even with statements in between.
func TestNullDeref_DerefArgCallKillsNull(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

typedef struct { uint32_t ulMsgLen; } MSGHEAD_S;

static uint32_t get_len(void) { return 8; }

void memset_s_init(void) {
    MSGHEAD_S *head = get_head();
    uint32_t total = get_len();
    total += 1;
    (void)memset_s(head, sizeof(*head) + total, 0, sizeof(*head) + total);
    total += 2;
    head->ulMsgLen = total;
}

void memcpy_init(void) {
    MSGHEAD_S *dst = get_head();
    MSGHEAD_S *src = get_head();
    memcpy(dst, src, sizeof(*dst));
    dst->ulMsgLen = 1;
}

void definite_deref_arg(void) {
    MSGHEAD_S *head = NULL;
    (void)memset_s(head, sizeof(*head), 0, sizeof(*head));
    head->ulMsgLen = 1;
}

void real_null(void) {
    MSGHEAD_S *head = NULL;
    head->ulMsgLen = 1;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "ik.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	byFunc := map[string]bool{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = true
	}
	if byFunc["memset_s_init"] {
		t.Errorf("memset_s_init's head (dereferenced by memset_s) must NOT be a null-deref, got: %v", byFunc)
	}
	if byFunc["memcpy_init"] {
		t.Errorf("memcpy_init's dst (dereferenced by memcpy) must NOT be a null-deref, got: %v", byFunc)
	}
	if byFunc["definite_deref_arg"] {
		t.Errorf("definite_deref_arg's head (dereferenced by memset_s before the use) must NOT be a null-deref, got: %v", byFunc)
	}
	if !byFunc["real_null"] {
		t.Errorf("real_null's head (plain NULL then deref) must stay a null-deref, got: %v", byFunc)
	}
	for _, c := range result.Candidates {
		if c.Target.Function == "real_null" && !c.HasDefiniteNull {
			t.Errorf("real_null must carry has_definite_null=true")
		}
	}
}
