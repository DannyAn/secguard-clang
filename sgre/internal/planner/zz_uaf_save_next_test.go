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

// Issue #253 P2-1: `next = p->next; free(p); use(next);` is the idiomatic safe
// list unlink — next aliases p's FIELD VALUE, not p itself, so it must never
// be auto-confirmed as use-after-free.
func TestLifetimeFilter_SaveNextThenFreeNotUAF(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	src := `#include <stdlib.h>
typedef struct node { int v; struct node *next; } node_t;

void save_next_then_free(node_t *p)
{
    node_t *next = p->next;
    free(p);
    next->v = 1;
}

void real_use_after_free(node_t *p)
{
    free(p);
    p->v = 2;
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "uaf_next.c")
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
	var control *EvidenceItem
	for i := range result.Candidates {
		c := &result.Candidates[i]
		if c.Target.Function == "save_next_then_free" && c.SuspicionLevel == "confirmed" {
			t.Errorf("next = p->next; free(p); use(next) must not auto-confirm UAF (next aliases the field value, not p)")
		}
		if c.Target.Function == "real_use_after_free" {
			control = c
		}
	}
	if control == nil {
		t.Fatalf("the genuine UAF control must stay a candidate (the save-next assertion would be vacuous otherwise), got %v", candidateNames(result))
	}
}
