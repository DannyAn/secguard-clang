package parser

import (
	"fmt"
	"sync"
	"testing"
)

// TestParseCached_Concurrent exercises the exact production pattern that the
// parallelized graph builders / detectors / planners depend on: many goroutines
// parsing the same small set of files through a single shared Parser. Before
// ParseCached was made thread-safe this was a "concurrent map writes" crash /
// data race, so this test is the regression guard (run with -race in CI).
func TestParseCached_Concurrent(t *testing.T) {
	p := NewParser()
	defer p.CloseAll()
	source := []byte(`int a(void) { return 1; }
int b(void) { return 2; }
int c(void) { return 3; }`)

	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Every goroutine parses the same file, plus a distinct one, so
			// both the cache-hit and cache-miss paths race under the old code.
			tree, err := p.ParseCached(source, "shared.c")
			if err != nil {
				t.Errorf("goroutine %d: ParseCached shared.c: %v", n, err)
				return
			}
			if root := tree.RootNode(); root.Kind() != "translation_unit" {
				t.Errorf("goroutine %d: unexpected root kind %q", n, root.Kind())
			}
			own := []byte(fmt.Sprintf("int f%d(void) { return %d; }", n, n))
			if _, err := p.ParseCached(own, fmt.Sprintf("own_%d.c", n)); err != nil {
				t.Errorf("goroutine %d: ParseCached own: %v", n, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestNewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Fatal("NewParser returned nil")
	}
}

func TestParseCSource(t *testing.T) {
	p := NewParser()
	source := []byte(`int main(void) { return 0; }`)
	tree, err := p.Parse(source, "test.c")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()
	if root.Kind() != "translation_unit" {
		t.Errorf("expected root kind 'translation_unit', got %q", root.Kind())
	}
}

func TestParse_HasErrorFlag(t *testing.T) {
	p := NewParser()
	source := []byte(`int broken( { return 0 }`)
	tree, _ := p.Parse(source, "broken.c")
	defer tree.Close()

	if !tree.HasError() {
		t.Error("expected HasError=true for syntax error file")
	}
}

func TestParse_FindAllFunctions(t *testing.T) {
	p := NewParser()
	source := []byte(`
int func_a(void) { return 1; }
static int func_b(int x) { return x; }
void func_c(void) { }
`)
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) != 3 {
		t.Errorf("expected 3 function_definition nodes, got %d", len(funcs))
	}
}

func TestNode_Text(t *testing.T) {
	p := NewParser()
	source := []byte(`int main(void) { return 42; }`)
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) == 0 {
		t.Fatal("no function_definition found")
	}
	text := funcs[0].Text()
	if text == "" {
		t.Error("expected non-empty function text")
	}
}

func TestNode_StartLine(t *testing.T) {
	p := NewParser()
	source := []byte("\n\nint main(void) {\n  return 0;\n}\n")
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) == 0 {
		t.Fatal("no function_definition found")
	}
	if funcs[0].StartLine() != 3 {
		t.Errorf("expected start line 3, got %d", funcs[0].StartLine())
	}
}

func TestNode_ChildByFieldName(t *testing.T) {
	p := NewParser()
	source := []byte(`int main(void) { return 0; }`)
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) == 0 {
		t.Fatal("no function_definition found")
	}
}
