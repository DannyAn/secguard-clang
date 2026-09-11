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

// TestLockOrderFilter_ConfirmsCycle pins the lock-order graph wiring: a deadlock
// candidate whose two mutexes are mutually reachable in the persisted LOCK_ORDER
// graph must be upgraded to "confirmed".
func TestLockOrderFilter_ConfirmsCycle(t *testing.T) {
	src := `#include <pthread.h>

pthread_mutex_t m1, m2;

void f(void) {
    pthread_mutex_lock(&m1);
    pthread_mutex_lock(&m2);
    pthread_mutex_unlock(&m2);
    pthread_mutex_unlock(&m1);
}

void g(void) {
    pthread_mutex_lock(&m2);
    pthread_mutex_lock(&m1);
    pthread_mutex_unlock(&m1);
    pthread_mutex_unlock(&m2);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "deadlock.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewLockOrderBuilder(store, p, logger).Build(ctx)
	evidence.NewDeadlockDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "deadlock")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	found := false
	for _, c := range result.Candidates {
		found = true
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("deadlock candidate should be confirmed by the lock-order graph, got %q", c.SuspicionLevel)
		}
	}
	if !found {
		t.Errorf("expected a deadlock candidate, got %v", candidateNames(result))
	}
}

// TestLockOrderFilter_TimedCycleStaysSuspected pins the timedlock tier: a cycle
// that includes a `pthread_mutex_timedlock` acquisition is a real lock-order
// inversion but can recover via ETIMEDOUT, so the detector must still report it
// (it used to miss it entirely) and the lock-order graph must NOT upgrade it to
// confirmed.
func TestLockOrderFilter_TimedCycleStaysSuspected(t *testing.T) {
	src := `#include <pthread.h>
#include <time.h>

pthread_mutex_t m1, m2;

void f(void) {
    struct timespec ts;
    pthread_mutex_lock(&m1);
    pthread_mutex_timedlock(&m2, &ts);
    pthread_mutex_unlock(&m2);
    pthread_mutex_unlock(&m1);
}

void g(void) {
    pthread_mutex_lock(&m2);
    pthread_mutex_lock(&m1);
    pthread_mutex_unlock(&m1);
    pthread_mutex_unlock(&m2);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "deadlock_timed.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewLockOrderBuilder(store, p, logger).Build(ctx)
	evidence.NewDeadlockDetector(store, p, logger).Detect(ctx)

	result, err := NewPlanner(store, p, logger).Plan(ctx, "deadlock")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	found := false
	for _, c := range result.Candidates {
		found = true
		if c.SuspicionLevel != "suspected" {
			t.Errorf("timedlock cycle should stay suspected (recoverable), got %q", c.SuspicionLevel)
		}
	}
	if !found {
		t.Errorf("expected a deadlock candidate for the timedlock cycle, got %v", candidateNames(result))
	}
}
