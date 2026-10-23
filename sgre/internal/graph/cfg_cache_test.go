package graph

import (
	"context"
	"sync"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestCFGCacheMissThenHit(t *testing.T) {
	c := NewCFGCache()
	calls := 0
	builder := func() *StmtCFG {
		calls++
		return &StmtCFG{Nodes: []*StmtNode{{ID: 1}}}
	}
	a := c.GetOrBuild(42, builder)
	b := c.GetOrBuild(42, builder)
	if calls != 1 {
		t.Fatalf("builder called %d times, want 1", calls)
	}
	if a != b {
		t.Fatalf("cache miss on second call: %p vs %p", a, b)
	}
	if c.Builds != 1 || c.Hits != 1 {
		t.Fatalf("stats: builds=%d hits=%d, want 1/1", c.Builds, c.Hits)
	}
}

func TestCFGCacheNilBuilderNotCached(t *testing.T) {
	c := NewCFGCache()
	calls := 0
	builder := func() *StmtCFG {
		calls++
		return nil
	}
	_ = c.GetOrBuild(7, builder)
	_ = c.GetOrBuild(7, builder)
	if calls != 2 {
		t.Fatalf("nil result must not be cached: builder called %d times, want 2", calls)
	}
	if c.Builds != 2 || c.Hits != 0 {
		t.Fatalf("stats: builds=%d hits=%d, want 2/0", c.Builds, c.Hits)
	}
}

func TestCFGCacheZeroAndNegativeIDsBypass(t *testing.T) {
	c := NewCFGCache()
	calls := 0
	builder := func() *StmtCFG {
		calls++
		return &StmtCFG{}
	}
	_ = c.GetOrBuild(0, builder)
	_ = c.GetOrBuild(-1, builder)
	_ = c.GetOrBuild(0, builder)
	if calls != 3 {
		t.Fatalf("non-positive IDs must bypass cache: calls=%d, want 3", calls)
	}
	if len(c.byFn) != 0 {
		t.Fatalf("cache map non-empty for bypassed IDs: %d entries", len(c.byFn))
	}
}

func TestCFGCacheConcurrent(t *testing.T) {
	c := NewCFGCache()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := int64((i % 10) + 1)
				c.GetOrBuild(id, func() *StmtCFG {
					return &StmtCFG{Nodes: []*StmtNode{{ID: int(id)}}}
				})
			}
		}(g)
	}
	wg.Wait()
	builds, hits := c.Stats()
	if builds != 10 {
		t.Fatalf("builds=%d, want 10 (one per distinct id)", builds)
	}
	if hits+builds != 8*200 {
		t.Fatalf("total accesses %d, want %d", hits+builds, 8*200)
	}
}

func TestCFGCacheInvalidateAndReset(t *testing.T) {
	c := NewCFGCache()
	c.GetOrBuild(1, func() *StmtCFG { return &StmtCFG{} })
	c.GetOrBuild(2, func() *StmtCFG { return &StmtCFG{} })
	c.Invalidate(1)
	if _, ok := c.byFn[1]; ok {
		t.Fatal("Invalidate did not drop fn 1")
	}
	if _, ok := c.byFn[2]; !ok {
		t.Fatal("Invalidate dropped wrong entry")
	}
	c.Reset()
	if len(c.byFn) != 0 || c.Builds != 0 || c.Hits != 0 {
		t.Fatal("Reset did not clear state")
	}
}

func TestBuildStmtCFGWithCache_NilCache(t *testing.T) {
	p := parser.NewParser()
	defer p.CloseAll()
	src := []byte("int f(void) { return 0; }")
	tree, err := p.Parse(src, "x.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := tree.RootNode()
	var body parser.Node
	var found bool
	var walk func(n parser.Node)
	walk = func(n parser.Node) {
		if !found && n.Kind() == "compound_statement" {
			body = n
			found = true
			return
		}
		for _, c := range n.Children() {
			walk(c)
		}
	}
	walk(root)
	if !found {
		t.Fatal("no compound_statement found")
	}
	cfg := BuildStmtCFGWithCache(nil, 0, body, 2)
	if cfg == nil {
		t.Fatal("nil cache path returned nil CFG")
	}
	_ = context.Background()
}
