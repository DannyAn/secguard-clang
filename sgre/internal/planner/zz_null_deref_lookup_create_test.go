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

// TestNullDeref_LookupOrCreate pins the lookup-or-create guard: `n = lookup();
// if (!n) n = create();` makes n non-null at the join (lookup found it, or the
// abort-on-OOM create() made it), so `n->x` is not a null-deref. This also pins
// the closure fix: the return-call callee `create` (which returns an
// abort-on-OOM xmalloc result) must be graded by the fixpoint, not by the
// "contains malloc" name heuristic.
func TestNullDeref_LookupOrCreate(t *testing.T) {
	src := `#include <stdlib.h>
struct Node { int x; };
void *xmalloc(size_t size) {
    void *p = malloc(size);
    if (!p) abort();
    return p;
}
struct Node *lookup(int k) {
    return (struct Node *)0;
}
struct Node *create(int k) {
    return (struct Node *)xmalloc(sizeof(struct Node));
}
void use(int k) {
    struct Node *n = lookup(k);
    if (!n) {
        n = create(k);
    }
    n->x = 1;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	defer p.CloseAll()
	dir := t.TempDir()
	path := filepath.Join(dir, "nd.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatal(err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)
	res, err := NewPlanner(store, p, logger).Plan(ctx, "null-deref")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Candidates {
		if c.Target.Function == "use" && c.Target.Variable == "n" {
			t.Errorf("lookup-or-create must make n non-null; got suspicion=%q hint=%q", c.SuspicionLevel, c.Hint)
		}
	}
}
