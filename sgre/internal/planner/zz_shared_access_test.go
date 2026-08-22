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

// TestSharedAccessFilter_ConfirmsRace pins the shared-access graph wiring: a
// shared-data-race candidate whose two thread functions write the same global in
// the persisted GLOBAL_ACCESS graph must be upgraded to "confirmed".
func TestSharedAccessFilter_ConfirmsRace(t *testing.T) {
	src := `#include <pthread.h>

int g_counter;

void *thread1(void *arg) {
    g_counter++;
    return NULL;
}

void *thread2(void *arg) {
    g_counter++;
    return NULL;
}

void f(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread1, NULL);
    pthread_create(&t2, NULL, thread2, NULL);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "race.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewSharedAccessBuilder(store, p, logger).Build(ctx)
	evidence.NewRaceConditionDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "race-condition")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	found := false
	for _, c := range result.Candidates {
		found = true
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("shared_data_race candidate should be confirmed by the GLOBAL_ACCESS graph, got %q", c.SuspicionLevel)
		}
	}
	if !found {
		t.Errorf("expected a shared_data_race candidate, got %v", candidateNames(result))
	}
}
