//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// TestDoubleFree_GlobalSlotMayFree pins the DF-05 shape: a release helper frees
// its argument conditionally (`if (ref_count <= 0) free(p)`), so a later cleanup
// of the global slot that still holds the released object is a POSSIBLE double
// free. The detector must (a) recognize the may-free through the call summary,
// (b) attribute the second free to the cleanup call site, and (c) mark the
// candidate may_free so the flow filter never upgrades it to confirmed.
func TestDoubleFree_GlobalSlotMayFree(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct item {
    int ref_count;
    char *buf;
} item_t;

static item_t *g_items[8];
static int g_count;

item_t *item_new(int n) {
    (void)n;
    item_t *it = malloc(sizeof(item_t));
    it->ref_count = 1;
    it->buf = malloc(16);
    g_items[g_count++] = it;
    return it;
}

void item_release(item_t *it) {
    if (!it) return;
    it->ref_count--;
    if (it->ref_count <= 0) {
        free(it->buf);
        it->buf = NULL;
        free(it);
    }
}

void item_cleanup_all(void) {
    for (int i = 0; i < g_count; i++) {
        if (g_items[i]) {
            free(g_items[i]->buf);
            free(g_items[i]);
        }
    }
    g_count = 0;
}

int main(void) {
    item_t *a = item_new(1);
    item_t *b = item_new(2);
    item_release(a);
    item_release(b);
    item_cleanup_all();
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "slot_may_free.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	if _, err := NewDoubleFreeDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "DOUBLE_FREE")
	if err != nil {
		t.Fatalf("list DOUBLE_FREE: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 DOUBLE_FREE event (slot cleanup after a may-release), got %d", len(events))
	}
	var props struct {
		Variable   string `json:"variable"`
		FirstFree  int    `json:"first_free"`
		SecondFree int    `json:"second_free"`
		MayFree    string `json:"may_free"`
		FirstCal   string `json:"first_callee"`
		Victims    string `json:"victims"`
	}
	if err := json.Unmarshal([]byte(events[0].Properties), &props); err != nil {
		t.Fatalf("unmarshal props: %v", err)
	}
	if props.Variable != "g_items[]" {
		t.Errorf("variable = %q, want the global slot g_items[]", props.Variable)
	}
	if props.MayFree != "true" {
		t.Errorf("may_free must be true (the release helper frees only on some paths), props=%s", events[0].Properties)
	}
	if props.FirstFree == 0 || props.SecondFree != 45 {
		t.Errorf("first_free/second_free = %d/%d, want a first free line and the item_cleanup_all() call at 45", props.FirstFree, props.SecondFree)
	}
	if props.FirstCal != "item_release" {
		t.Errorf("first_callee = %q, want item_release (the may-free helper), props=%s", props.FirstCal, events[0].Properties)
	}
	if props.Victims == "" {
		t.Errorf("victims must name the stored values, props=%s", events[0].Properties)
	}

	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "double-free")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(res.Candidates) != 1 {
		t.Fatalf("expected 1 double-free candidate, got %d", len(res.Candidates))
	}
	c := res.Candidates[0]
	if c.SuspicionLevel == "confirmed" {
		t.Errorf("a may-free double free must stay suspected (never machine-confirmed), got %q", c.SuspicionLevel)
	}
	if !c.MayFree {
		t.Errorf("candidate must carry MayFree=true, got %+v", c)
	}
	if c.Target.Line != 45 {
		t.Errorf("candidate line = %d, want the cleanup call site 45", c.Target.Line)
	}
}
