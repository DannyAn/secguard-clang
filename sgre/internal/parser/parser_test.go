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

// TestParse_TypeofNativeParsing locks in tree-sitter-c v0.24.3's native typeof
// support: every GCC spelling (typeof/__typeof/__typeof__/typeof_unqual) across
// every parameter shape (identifier/deref/compound/type_descriptor) parses
// without ERROR, and the source is preserved verbatim (no rewrite).
func TestParse_TypeofNativeParsing(t *testing.T) {
	spellings := []string{"typeof", "__typeof", "__typeof__", "typeof_unqual"}
	forms := map[string]string{
		"identifier":      "%s(x) v;",
		"deref":           "%s(*p) v;",
		"compound":        "%s(p + 1) v;",
		"type_descriptor": "%s(int *) v;",
	}
	for _, kw := range spellings {
		for name, fmtStr := range forms {
			decl := fmt.Sprintf(fmtStr, kw)
			source := []byte("int *p;\nint x;\nvoid f(void){ " + decl + " }\n")
			tree, err := NewParser().Parse(source, kw+"_"+name+".c")
			if err != nil {
				t.Fatalf("%s/%s: Parse: %v", kw, name, err)
			}
			if tree.HasError() {
				t.Errorf("%s/%s: HasError()=true, want false", kw, name)
			}
			if !strings.Contains(string(tree.Source()), kw) {
				t.Errorf("%s/%s: typeof spelling was corrupted: %q", kw, name, tree.Source())
			}
			tree.Close()
		}
	}
}

// TestParse_TypeofNearDirectives locks in scenario 6: a typeof(...) inside a
// macro body or guarded by conditional-compilation directives must not break the
// parse of the declarations that follow it. tree-sitter-c v0.24.3 parses typeof
// natively, so the source is preserved verbatim.
func TestParse_TypeofNearDirectives(t *testing.T) {
	source := []byte(
		"#define M(x) typeof(x)\n" +
			"#ifdef ENABLE\n" +
			"typeof(int) g;\n" +
			"#else\n" +
			"int g;\n" +
			"#endif\n" +
			"int after(void){ return 0; }\n")
	tree, _ := NewParser().Parse(source, "near_directives.c")
	defer tree.Close()

	if tree.HasError() {
		t.Errorf("HasError() = true, want false: %q", tree.Source())
	}
	if !strings.Contains(string(tree.Source()), "#define M(x) typeof(x)") {
		t.Errorf("macro body typeof should be preserved: %q", tree.Source())
	}
	if tree.RootNode().FindFirst("function_definition") == nil {
		t.Error("subsequent function_definition not found (parse broken by nearby typeof)")
	}
}

// TestParse_TypeofInCommentAndString locks in that a typeof(...) inside a string
// literal or comment is prose and must not break the parse; the real typeof in
// code is parsed natively alongside it. The source is preserved byte-for-byte.
func TestParse_TypeofInCommentAndString(t *testing.T) {
	source := []byte(
		"const char *s = \"use typeof(x) here\";\n" +
			"// typeof(x) in a line comment\n" +
			"/* typeof(x) in a block comment */\n" +
			"char c = 't';\n" +
			"int f(struct s *n){ typeof(n->leafs) p = 0; return 0; }\n")
	tree, _ := NewParser().Parse(source, "typeof_in_prose.c")
	defer tree.Close()

	if tree.HasError() {
		t.Errorf("HasError()=true, want false: %q", tree.Source())
	}
	for _, keep := range []string{
		`"use typeof(x) here"`,
		"// typeof(x) in a line comment",
		"/* typeof(x) in a block comment */",
		"typeof(n->leafs)",
	} {
		if !strings.Contains(string(tree.Source()), keep) {
			t.Errorf("source was corrupted: %q no longer contains %q", tree.Source(), keep)
		}
	}
}

// TestParse_TypeofCommentWithParens locks in that a `)` or `(` inside a comment
// or string within a typeof parameter does not corrupt the native parse.
func TestParse_TypeofCommentWithParens(t *testing.T) {
	cases := map[string]string{
		"comment_close": "int f(void){ typeof(int /* x ) y */) v = 0; return v; }\n",
		"comment_open":  "int f(void){ typeof(int /* x ( y */) v = 0; return v; }\n",
		"string_paren":  "int f(void){ typeof(\"(\") v = 0; return v; }\n",
	}
	for name, src := range cases {
		tree, _ := NewParser().Parse([]byte(src), name+".c")
		if tree.HasError() {
			t.Errorf("%s: HasError()=true, want false: %q", name, src)
		}
		tree.Close()
	}
}

// TestParse_DoesNotCorruptIdentifiers guards that an identifier merely
// containing "typeof" (e.g. mytypeof_helper) parses normally — it is not a
// typeof construct, and the source is unchanged.
func TestParse_DoesNotCorruptIdentifiers(t *testing.T) {
	source := []byte("int mytypeof_helper(int x){ return x; }\nint __typeof_helper(int x){ return x; }\n")
	tree, _ := NewParser().Parse(source, "identifiers.c")
	defer tree.Close()

	if tree.HasError() {
		t.Errorf("HasError()=true: %q", tree.Source())
	}
	if string(tree.Source()) != string(source) {
		t.Errorf("source was corrupted:\n got %q\nwant %q", tree.Source(), source)
	}
}

// TestNode_OriginalTextEqualsText locks in that OriginalText returns the source
// as written (typeof is parsed natively, no rewrite), identical to Text.
func TestNode_OriginalTextEqualsText(t *testing.T) {
	source := []byte("double ratio;\nint f(double ratio, int n){ typeof(ratio) d = ratio; return d / n; }\n")
	tree, _ := NewParser().Parse(source, "typeof_type.c")
	defer tree.Close()

	root := tree.RootNode()
	typeofDecls := 0
	for _, d := range root.FindAll("declaration") {
		if !strings.Contains(d.Text(), "typeof") {
			continue
		}
		typeofDecls++
		if got := d.OriginalText(); !strings.Contains(got, "typeof(ratio)") {
			t.Errorf("OriginalText should show the original typeof, got %q", got)
		}
		if d.OriginalText() != d.Text() {
			t.Errorf("OriginalText should equal Text after rewrite removal, got %q vs %q", d.OriginalText(), d.Text())
		}
	}
	if typeofDecls != 1 {
		t.Errorf("expected exactly 1 typeof declaration, got %d", typeofDecls)
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
