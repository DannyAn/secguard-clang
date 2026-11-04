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
func TestCFGCache_LRUMaxEntries(t *testing.T) {
	c := NewCFGCache()
	c.MaxEntries = 3
	for i := int64(1); i <= 5; i++ {
		c.GetOrBuild(i, func() *StmtCFG {
			return &StmtCFG{Nodes: []*StmtNode{{ID: int(i)}}}
		})
	}
	_, _, _, entries, _ := c.StatsFull()
	if entries > 3 {
		t.Fatalf("entries=%d, want <= 3", entries)
	}
	if c.Evictions != 2 {
		t.Fatalf("evictions=%d, want 2", c.Evictions)
	}
	for k := int64(1); k <= 2; k++ {
		if _, ok := c.byFn[k]; ok {
			t.Fatalf("fn %d should have been evicted", k)
		}
	}
	for k := int64(3); k <= 5; k++ {
		if _, ok := c.byFn[k]; !ok {
			t.Fatalf("fn %d should still be cached", k)
		}
	}
}

func TestCFGCache_LRUMaxTotalNodes(t *testing.T) {
	c := NewCFGCache()
	c.MaxTotalCFGNodes = 10
	sizes := []int{3, 4, 5}
	for i, sz := range sizes {
		id := int64(i + 1)
		nodes := make([]*StmtNode, sz)
		for j := range nodes {
			nodes[j] = &StmtNode{ID: j}
		}
		c.GetOrBuild(id, func() *StmtCFG { return &StmtCFG{Nodes: nodes} })
	}
	_, _, _, _, tn := c.StatsFull()
	if tn > 10 {
		t.Fatalf("totalNodes=%d, want <= 10", tn)
	}
	if c.Evictions == 0 {
		t.Fatal("expected at least 1 eviction")
	}
}

func TestCFGCache_LRUAccessRefreshesTimestamp(t *testing.T) {
	c := NewCFGCache()
	c.MaxEntries = 2
	c.GetOrBuild(1, func() *StmtCFG { return &StmtCFG{} })
	c.GetOrBuild(2, func() *StmtCFG { return &StmtCFG{} })
	c.GetOrBuild(1, func() *StmtCFG { return &StmtCFG{} })
	c.GetOrBuild(3, func() *StmtCFG { return &StmtCFG{} })
	if _, ok := c.byFn[1]; !ok {
		t.Fatal("fn 1 should still be cached (accessed most recently)")
	}
	if _, ok := c.byFn[2]; ok {
		t.Fatal("fn 2 should have been evicted (oldest)")
	}
	if _, ok := c.byFn[3]; !ok {
		t.Fatal("fn 3 should be cached (just inserted)")
	}
}

func TestCFGCache_UnboundedByDefault(t *testing.T) {
	c := NewCFGCache()
	for i := int64(1); i <= 100; i++ {
		c.GetOrBuild(i, func() *StmtCFG { return &StmtCFG{} })
	}
	_, _, _, entries, _ := c.StatsFull()
	if entries != 100 {
		t.Fatalf("unbounded cache entries=%d, want 100", entries)
	}
	if c.Evictions != 0 {
		t.Fatalf("unbounded cache evictions=%d, want 0", c.Evictions)
	}
}

func TestCFGCache_StatsFull(t *testing.T) {
	c := NewCFGCache()
	c.MaxEntries = 2
	c.GetOrBuild(1, func() *StmtCFG { return &StmtCFG{Nodes: []*StmtNode{{ID: 1}, {ID: 2}}} })
	c.GetOrBuild(2, func() *StmtCFG { return &StmtCFG{Nodes: []*StmtNode{{ID: 1}}} })
	c.GetOrBuild(3, func() *StmtCFG { return &StmtCFG{Nodes: []*StmtNode{{ID: 1}, {ID: 2}, {ID: 3}}} })
	b, h, e, n, tn := c.StatsFull()
	if b != 3 {
		t.Fatalf("builds=%d, want 3", b)
	}
	if h != 0 {
		t.Fatalf("hits=%d, want 0", h)
	}
	if e != 1 {
		t.Fatalf("evictions=%d, want 1", e)
	}
	if n != 2 {
		t.Fatalf("entries=%d, want 2", n)
	}
	if tn <= 0 {
		t.Fatalf("totalNodes=%d, want > 0", tn)
	}
}
