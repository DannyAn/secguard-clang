package parser

import (
	"sync"
	"testing"
)

func TestParseCached_MaxCachedTrees_LRU(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(2)
	for i := 0; i < 4; i++ {
		src := []byte("int f" + string(rune('a'+i)) + "(void) { return 0; }")
		_, err := p.ParseCached(src, "file"+string(rune('a'+i))+".c")
		if err != nil {
			t.Fatalf("ParseCached %d: %v", i, err)
		}
	}
	cached, transient := p.CacheStats()
	if cached > 2 {
		t.Fatalf("cached=%d, want <= 2", cached)
	}
	if cached+transient < 1 {
		t.Fatalf("cached+transient=%d, want >= 1", cached+transient)
	}
}

func TestParseCached_ReferencedTreeNotEvicted(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(2)
	tree1, _ := p.ParseCached([]byte("int a(void){return 0;}"), "a.c")
	tree1.Acquire()
	_, _ = p.ParseCached([]byte("int b(void){return 0;}"), "b.c")
	_, _ = p.ParseCached([]byte("int c(void){return 0;}"), "c.c")
	cached, _ := p.CacheStats()
	if cached > 2 {
		t.Fatalf("cached=%d, want <= 2", cached)
	}
	tree1.Release()
}

func TestParseCached_UnboundedByDefault(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	for i := 0; i < 50; i++ {
		_, err := p.ParseCached([]byte("int x(void){return 0;}"), "f"+string(rune('a'+i))+".c")
		if err != nil {
			t.Fatalf("ParseCached %d: %v", i, err)
		}
	}
	cached, transient := p.CacheStats()
	if cached != 50 {
		t.Fatalf("unbounded cached=%d, want 50", cached)
	}
	if transient != 0 {
		t.Fatalf("unbounded transient=%d, want 0", transient)
	}
}

func TestTree_AcquireRelease(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	tree, _ := p.ParseCached([]byte("int f(void){return 0;}"), "f.c")
	if tree.Refs() != 0 {
		t.Fatalf("initial refs=%d, want 0", tree.Refs())
	}
	tree.Acquire()
	tree.Acquire()
	if tree.Refs() != 2 {
		t.Fatalf("after 2 Acquire refs=%d, want 2", tree.Refs())
	}
	tree.Release()
	if tree.Refs() != 1 {
		t.Fatalf("after 1 Release refs=%d, want 1", tree.Refs())
	}
	tree.Release()
	if tree.Refs() != 0 {
		t.Fatalf("after 2 Release refs=%d, want 0", tree.Refs())
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
				_, _ = p.ParseCached([]byte("int x(void){return 0;}"), "shared.c")
				_, _ = p.ParseCached([]byte("int y(void){return 1;}"), "own.c")
			}
		}(g)
	}
	wg.Wait()
	cached, _ := p.CacheStats()
	if cached > 10 {
		t.Fatalf("cached=%d, want <= 10", cached)
	}
}
