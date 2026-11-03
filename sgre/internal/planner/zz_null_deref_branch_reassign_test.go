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

// TestNullDeref_BranchReassignKillsDefiniteNull pins the A.7c proof error: a
// pointer assigned NULL then reassigned to a non-null address-of inside EVERY
// non-returning branch (with the remaining branch returning) must NOT be
// auto-confirmed as a certain null-deref. Before the fix the dereference inside
// the nested `if (*p == 0)` body resolved to the else-if HEADER node (whose
// incoming definite-null fact still held), so the pipeline claimed "no
// intervening reassignment" and auto-confirmed a false CWE-476.
func TestNullDeref_BranchReassignKillsDefiniteNull(t *testing.T) {
	src := `#include <stdint.h>
#include <stddef.h>

typedef struct { uint16_t num; } Cfg;
typedef struct { int x; } Zone;

enum { FLAG_A = 1, FLAG_B = 2 };

void del(Zone *z, Cfg *c, uint32_t flag)
{
    uint16_t *p = NULL;
    if (flag == FLAG_A) {
        p = &c->num;
        if (*p == 0) {
            return;
        }
    } else if (flag == FLAG_B) {
        p = &c->num;
        if (*p == 0) {
            return;
        }
    } else {
        return;
    }
    *p = 0;
    (void)z;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "a.c")
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
	for _, c := range result.Candidates {
		if c.Target.Variable == "p" {
			if c.HasDefiniteNull {
				t.Errorf("p (reassigned to &c->num on every non-returning branch) must NOT carry has_definite_null")
			}
			if c.SuspicionLevel == "confirmed" {
				t.Errorf("p must not be auto-confirmed, got %q", c.SuspicionLevel)
			}
		}
	}
}
