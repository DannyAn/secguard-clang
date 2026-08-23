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

const rcFixture = `#include <stdlib.h>
#include <string.h>

typedef struct { char *buffer; size_t size; } Entry;

int tp_bare_call(void) {
    malloc(16);
    return 0;
}

int tp_assigned_not_checked(void) {
    char *p = (char *)malloc(16);
    p[0] = 'x';
    return 0;
}

int fp_assigned_and_checked(void) {
    char *p = (char *)malloc(16);
    if (!p) return -1;
    p[0] = 'x';
    return 0;
}

int fp_decl_and_checked(void) {
    char *p = (char *)malloc(16);
    if (p == NULL) return -1;
    p[0] = 'x';
    return 0;
}

int tp_outer_unchecked_inner_member_checked(void) {
    Entry *e = (Entry *)malloc(sizeof(Entry));
    e->buffer = (char *)malloc(16);
    if (!e->buffer) { free(e); return -1; }
    return 0;
}

int tp_complex_unknown(void) {
    char *p = (char *)malloc(16);
    char *q = p;
    q[0] = 'x';
    return 0;
}

int tp_field_use_not_nullcheck(void) {
    Entry *e = (Entry *)malloc(sizeof(Entry));
    if (e->size > 0) {
        return (int)e->size;
    }
    return 0;
}
`

func TestReturnCheckFilter_Convergence(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "rc.c")
	if err := os.WriteFile(path, []byte(rcFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUncheckedReturnDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "unchecked-return")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	suspicions := make(map[string]string)
	for _, c := range result.Candidates {
		suspicions[c.Target.Function] = c.SuspicionLevel
	}

	if s := suspicions["tp_bare_call"]; s != "confirmed" {
		t.Errorf("tp_bare_call: expected confirmed (bare call), got %s", s)
	}
	if s := suspicions["tp_assigned_not_checked"]; s != "confirmed" {
		t.Errorf("tp_assigned_not_checked: expected confirmed (assigned but never checked), got %s", s)
	}
	if _, ok := suspicions["fp_assigned_and_checked"]; ok {
		t.Errorf("fp_assigned_and_checked: expected dismissed, got candidate")
	}
	if _, ok := suspicions["fp_decl_and_checked"]; ok {
		t.Errorf("fp_decl_and_checked: expected dismissed, got candidate")
	}
	if s := suspicions["tp_outer_unchecked_inner_member_checked"]; s != "confirmed" {
		// The INNER `e->buffer = malloc` is checked (`if (!e->buffer)`), but the
		// OUTER `Entry *e = malloc` is never null-checked before `e->buffer` is
		// dereferenced — a genuine CWE-252 defect the detector no longer
		// suppresses, so it must stay confirmed (not be dismissed).
		t.Errorf("tp_outer_unchecked_inner_member_checked: expected confirmed (outer allocation unchecked, only e->buffer is checked), got %q", s)
	}
	if s := suspicions["tp_field_use_not_nullcheck"]; s != "confirmed" {
		t.Errorf("tp_field_use_not_nullcheck: expected confirmed (condition dereferences e->size, does not check e), got %s", s)
	}
}
