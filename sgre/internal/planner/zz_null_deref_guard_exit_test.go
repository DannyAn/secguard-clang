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

func planNullDerefGuardExit(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "guard_exit.c")
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
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewInterproceduralDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// TestNullDeref_ContinueGuard pins the loop-exit guard idiom: a
// `if (p == NULL) { ...; continue; }` establishes p non-null on the fall-through
// of the current loop iteration, so passing p to a callee that dereferences it
// (interprocedural null-deref) must not be flagged. The early-return guard
// detector previously only recognized `return` and missed `continue`.
func TestNullDeref_ContinueGuard(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct example_kafka_bufmsg { int x; } example_kafka_bufmsg_t;

void *g_rdkafka_lfrb;

int example_lfrb_try_pop(void *l);
example_kafka_bufmsg_t *example_lfrb_get_buf(void *l, int t);
void example_lfrb_pop(void *l);

void example_rdkafka_producer_send(example_kafka_bufmsg_t *b) {
    b->x = 1;
}

void example_produce_event(void)
{
    int t;
    for (;;) {
        if (g_rdkafka_lfrb == NULL) {
            break;
        }
        t = example_lfrb_try_pop(g_rdkafka_lfrb);
        if (t < 0) {
            break;
        }
        example_kafka_bufmsg_t *log_buf = (example_kafka_bufmsg_t *)example_lfrb_get_buf(g_rdkafka_lfrb, t);
        if (log_buf == NULL) {
            example_lfrb_pop(g_rdkafka_lfrb);
            continue;
        }
        (void)example_rdkafka_producer_send(log_buf);

        example_lfrb_pop(g_rdkafka_lfrb);
    }
    return;
}
`
	result := planNullDerefGuardExit(t, src)
	if c := candidateForFunc(t, result, "example_produce_event"); c != nil {
		t.Errorf("example_produce_event should NOT be flagged (log_buf is null-guarded by the continue), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// TestNullDeref_ContinueGuard_Control is the control: the same interprocedural
// shape WITHOUT the null guard must still be flagged, so the continue-guard
// suppression does not hide a genuine missing check.
func TestNullDeref_ContinueGuard_Control(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct example_kafka_bufmsg { int x; } example_kafka_bufmsg_t;

void *g_rdkafka_lfrb;

example_kafka_bufmsg_t *example_lfrb_get_buf(void *l, int t);
void example_lfrb_pop(void *l);

void example_rdkafka_producer_send(example_kafka_bufmsg_t *b) {
    b->x = 1;
}

void example_produce_event_unguarded(void)
{
    example_kafka_bufmsg_t *log_buf = (example_kafka_bufmsg_t *)example_lfrb_get_buf(g_rdkafka_lfrb, 0);
    (void)example_rdkafka_producer_send(log_buf);
    example_lfrb_pop(g_rdkafka_lfrb);
    return;
}
`
	result := planNullDerefGuardExit(t, src)
	if c := candidateForFunc(t, result, "example_produce_event_unguarded"); c == nil {
		t.Errorf("example_produce_event_unguarded should STAY flagged (log_buf is passed to a dereferencing callee without a null check)")
	}
}
