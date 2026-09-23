package parser

import (
	"fmt"
	"strings"
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

// TestParse_TypeofSpellings locks in the GCC typeof preprocessing for every
// spelling a real GNU C project uses. tree-sitter-c v0.24.2 has no typeof rule,
// so without preprocessing each of these fragments the AST (HasError=true) and
// the unchecked-return / null-source detectors lose the assignment chain.
func TestParse_TypeofSpellings(t *testing.T) {
	spellings := []string{"typeof", "__typeof", "__typeof__", "typeof_unqual"}
	for _, kw := range spellings {
		source := []byte(
			"void *x_malloc(int id, unsigned int size);\n" +
				"int f(struct s *n){ " + kw + "(n->leafs) leafs = (" + kw + "(n->leafs))x_malloc(1, 4); " +
				"if(leafs == NULL) return 1; return 0; }\n")
		tree, err := NewParser().Parse(source, kw+".c")
		if err != nil {
			t.Fatalf("%s: Parse: %v", kw, err)
		}
		if tree.HasError() {
			t.Errorf("%s: HasError() = true, want false (typeof not preprocessed)", kw)
		}
		tree.Close()
	}
}

// TestPreprocess_DoesNotCorruptIdentifiers guards the word-boundary check: an
// identifier that merely CONTAINS "typeof" (e.g. mytypeof_helper) must be left
// untouched, not mangled into `void *`.
func TestPreprocess_DoesNotCorruptIdentifiers(t *testing.T) {
	source := []byte("int mytypeof_helper(int x){ return x; }\nint __typeof_helper(int x){ return x; }\n")
	got := string(preprocessGccExtensions(source))
	if got != string(source) {
		t.Errorf("identifier containing typeof was corrupted:\n got %q\nwant %q", got, string(source))
	}
}

// TestPreprocess_DoesNotCorruptStringsOrComments guards the literal/comment
// skip: a `typeof(...)` inside a string literal or comment is prose, not a type
// construct, and must be left byte-for-byte intact (rewriting it would silently
// change what string-reading detectors such as hardcoded-secret see).
func TestPreprocess_DoesNotCorruptStringsOrComments(t *testing.T) {
	source := []byte(
		"const char *s = \"use typeof(x) here\";\n" +
			"// typeof(x) in a line comment\n" +
			"/* typeof(x) in a block comment */\n" +
			"char c = 't';\n" +
			"int f(struct s *n){ typeof(n->leafs) p = 0; return 0; }\n")
	got := string(preprocessGccExtensions(source))
	for _, keep := range []string{
		`"use typeof(x) here"`,
		"// typeof(x) in a line comment",
		"/* typeof(x) in a block comment */",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("literal/comment was corrupted: %q no longer contains %q", got, keep)
		}
	}
	// The real typeof in code IS still rewritten (not swallowed by the skip).
	if strings.Contains(got, "typeof(n->leafs)") {
		t.Errorf("real typeof in code was not rewritten:\n got %q", got)
	}
	if !strings.Contains(got, "void *") {
		t.Errorf("expected void * replacement, got %q", got)
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

// TestNode_ZeroValue_Kind guards the flow-filter safety net: fileParseCache can
// return a zero-value Node when a file re-read fails or a function_definition
// has no compound_statement body. Calling Kind() on that zero Node used to
// dereference a nil C TSNode and segfault the process (unrecoverable by Go's
// recover). It must now return "" so `if body.Kind() != "compound_statement"`
// skips the function instead of crashing.
func TestNode_ZeroValue_Kind(t *testing.T) {
	var n Node
	if got := n.Kind(); got != "" {
		t.Errorf("zero-value Node.Kind() = %q, want empty string", got)
	}
	if !n.isNull() {
		t.Error("zero-value Node should report isNull() == true")
	}
}
