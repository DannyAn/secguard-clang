package parser

import (
	"strings"
	"sync"
	"testing"
)

func TestParseCached_MaxCachedTrees_LRU(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(2)
	for i := 0; i < 4; i++ {
		tree, err := p.ParseCached([]byte("int f"+string(rune('a'+i))+"(void) { return 0; }"), "file"+string(rune('a'+i))+".c")
		if err != nil {
			t.Fatalf("ParseCached %d: %v", i, err)
		}
		tree.Release()
	}
	cached, transient := p.CacheStats()
	if cached > 2 {
		t.Fatalf("cached=%d, want <= 2", cached)
	}
	if transient != 0 {
		t.Fatalf("transient=%d, want 0 (each borrow was released)", transient)
	}
	if leaks := p.LeakedTrees(); len(leaks) != 0 {
		t.Fatalf("unexpected leaks: %v", leaks)
	}
}

func TestParseCached_ReferencedTreeNotEvicted(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(2)
	tree1, _ := p.ParseCached([]byte("int a(void){return 0;}"), "a.c")
	// tree1 carries the ParseCached borrow. Parse two more files; the cache is
	// allowed to evict the unreferenced b.c but must not evict the borrowed a.c.
	for _, name := range []string{"b.c", "c.c"} {
		tr, _ := p.ParseCached([]byte("int x(void){return 0;}"), name)
		tr.Release()
	}
	cached, transient := p.CacheStats()
	if cached > 2 {
		t.Fatalf("cached=%d, want <= 2", cached)
	}
	if transient != 0 {
		t.Fatalf("transient=%d, want 0", transient)
	}
	tree1.Release()
}

func TestParseCached_UnboundedByDefault(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	var trees []*Tree
	for i := 0; i < 50; i++ {
		tr, err := p.ParseCached([]byte("int x(void){return 0;}"), "f"+string(rune('a'+i))+".c")
		if err != nil {
			t.Fatalf("ParseCached %d: %v", i, err)
		}
		trees = append(trees, tr)
	}
	cached, transient := p.CacheStats()
	if cached != 50 {
		t.Fatalf("unbounded cached=%d, want 50", cached)
	}
	if transient != 0 {
		t.Fatalf("unbounded transient=%d, want 0", transient)
	}
	for _, tr := range trees {
		tr.Release()
	}
}

func TestTree_AcquireRelease(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	tree, _ := p.ParseCached([]byte("int f(void){return 0;}"), "f.c")
	if tree.Refs() != 1 {
		t.Fatalf("ParseCached borrow refs=%d, want 1", tree.Refs())
	}
	tree.Acquire()
	tree.Acquire()
	if tree.Refs() != 3 {
		t.Fatalf("after 2 Acquire refs=%d, want 3", tree.Refs())
	}
	tree.Release()
	if tree.Refs() != 2 {
		t.Fatalf("after 1 Release refs=%d, want 2", tree.Refs())
	}
	tree.Release()
	tree.Release()
	if tree.Refs() != 0 {
		t.Fatalf("after 3 Release refs=%d, want 0", tree.Refs())
	}
}

func TestParseCached_Concurrent_WithBound(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(10)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if tr, err := p.ParseCached([]byte("int x(void){return 0;}"), "shared.c"); err == nil {
					tr.Release()
				}
				if tr, err := p.ParseCached([]byte("int y(void){return 1;}"), "own.c"); err == nil {
					tr.Release()
				}
			}
		}(g)
	}
	wg.Wait()
	cached, transient := p.CacheStats()
	if cached > 10 {
		t.Fatalf("cached=%d, want <= 10", cached)
	}
	if transient != 0 {
		t.Fatalf("transient=%d, want 0", transient)
	}
}

func TestParseCached_TransientClosesOnRelease(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(1)
	pinned, _ := p.ParseCached([]byte("int a(void){return 0;}"), "a.c")
	transient, err := p.ParseCached([]byte("int b(void){return 1;}"), "b.c")
	if err != nil {
		t.Fatalf("transient parse: %v", err)
	}
	if transient.RootNode().Kind() != "translation_unit" {
		t.Fatal("transient tree must be usable while borrowed")
	}
	cached, active := p.CacheStats()
	if cached != 1 || active != 1 {
		t.Fatalf("cached/transient=%d/%d, want 1/1", cached, active)
	}
	transient.Release()
	if transient.RootNode().Kind() != "" {
		t.Fatal("transient tree must be closed by its final Release")
	}
	if _, active := p.CacheStats(); active != 0 {
		t.Fatalf("transient after release=%d, want 0", active)
	}
	pinned.Release()
}

func TestParseCached_TransientNoAccumulation(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(1)
	pinned, _ := p.ParseCached([]byte("int a(void){return 0;}"), "a.c")
	for i := 0; i < 100; i++ {
		tr, err := p.ParseCached([]byte("int b(void){return 1;}"), "b"+string(rune('a'+i%26))+".c")
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		tr.Release()
	}
	cached, active := p.CacheStats()
	if cached != 1 {
		t.Fatalf("cached=%d, want 1", cached)
	}
	if active != 0 {
		t.Fatalf("transient=%d, want 0 (transient trees must close on Release)", active)
	}
	pinned.Release()
}

func TestParseCached_CloseAllDefersBorrowed(t *testing.T) {
	p := NewParser()
	tr, _ := p.ParseCached([]byte("int a(void){return 0;}"), "a.c")
	p.CloseAll()
	leaks := p.LeakedTrees()
	if len(leaks) == 0 {
		t.Fatal("CloseAll must report a tree that still has a borrow")
	}
	if !strings.Contains(leaks[0], "a.c") {
		t.Fatalf("leak diagnostic %q does not name the file", leaks[0])
	}
	tr.Release()
	if tr.RootNode().Kind() != "" {
		t.Fatal("deferred close must run on the final Release")
	}
}

func TestWithParseCached_Releases(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(1)
	var seen string
	if err := p.WithParseCached([]byte("int a(void){return 0;}"), "a.c", func(tr *Tree) {
		seen = tr.RootNode().Kind()
	}); err != nil {
		t.Fatalf("WithParseCached: %v", err)
	}
	if seen != "translation_unit" {
		t.Fatalf("kind=%q", seen)
	}
	if cached, active := p.CacheStats(); cached != 1 || active != 0 {
		t.Fatalf("cached/transient=%d/%d, want 1/0", cached, active)
	}
}
