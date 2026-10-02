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

// TestParse_TypeofExpressionForms locks in the four typeof parameter shapes the
// user's regression plan calls out. tree-sitter-c v0.24.2 cannot parse typeof, so
// each must be rewritten to `void *` (length-preserving) and parse without error,
// rather than leaving an ERROR node that silently breaks the declaration.
func TestParse_TypeofExpressionForms(t *testing.T) {
	forms := map[string]string{
		"identifier":      "typeof(x) v;",
		"deref":           "typeof(*p) v;",
		"compound":        "typeof(p + 1) v;",
		"type_descriptor": "typeof(int *) v;",
	}
	for name, decl := range forms {
		source := []byte("int *p;\nint x;\nvoid f(void){ " + decl + " }\n")
		tree, err := NewParser().Parse(source, name+".c")
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		if tree.HasError() {
			t.Errorf("%s: HasError() = true, want false (rewritten: %q)", name, tree.Source())
		}
		if strings.Contains(string(tree.Source()), "typeof") {
			t.Errorf("%s: typeof was not rewritten: %q", name, tree.Source())
		}
		tree.Close()
	}
}

// TestParse_TypeofNearDirectives locks in scenario 6: a typeof(...) inside a
// macro body or guarded by conditional-compilation directives must not break the
// parse of the declarations that follow it. The macro body is preserved verbatim
// (it is not code); the guarded code declaration is still rewritten.
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
		t.Errorf("HasError() = true, want false (rewritten: %q)", tree.Source())
	}
	if !strings.Contains(string(tree.Source()), "#define M(x) typeof(x)") {
		t.Errorf("macro body typeof should be preserved: %q", tree.Source())
	}
	if tree.RootNode().FindFirst("function_definition") == nil {
		t.Error("subsequent function_definition not found (parse broken by nearby typeof)")
	}
}

// TestPreprocess_DoesNotCorruptIdentifiers guards the word-boundary check: an
// identifier that merely CONTAINS "typeof" (e.g. mytypeof_helper) must be left
// untouched, not mangled into `void *`.
func TestPreprocess_DoesNotCorruptIdentifiers(t *testing.T) {
	source := []byte("int mytypeof_helper(int x){ return x; }\nint __typeof_helper(int x){ return x; }\n")
	out, _ := preprocessGccExtensions(source)
	got := string(out)
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
	out, _ := preprocessGccExtensions(source)
	got := string(out)
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

// TestPreprocess_TypeofCommentWithCloseParen locks in TF-01: a `)` inside a
// comment in the typeof parameter must not end the parenthesis-balance scan
// early. Before the fix the rewrite truncated inside the comment, leaving a bare
// `*/)` and a parse error; now the comment is skipped and the construct is
// rewritten as one unit.
func TestPreprocess_TypeofCommentWithCloseParen(t *testing.T) {
	source := []byte("int f(void){ typeof(int /* x ) y */) v = 0; return v; }\n")
	out, rewrites := preprocessGccExtensions(source)
	tree, _ := NewParser().Parse(source, "comment_close_paren.c")
	defer tree.Close()

	if len(rewrites) != 1 {
		t.Fatalf("expected 1 rewrite, got %d (rewritten: %q)", len(rewrites), string(out))
	}
	if tree.HasError() {
		t.Errorf("HasError() = true, want false; rewritten: %q", string(out))
	}
	if !strings.Contains(string(out), "void *") {
		t.Errorf("expected void * replacement, got %q", string(out))
	}
	// The original source (used for evidence text) still holds the comment.
	if !strings.Contains(tree.RootNode().OriginalText(), "/* x ) y */") {
		t.Errorf("OriginalText lost the comment: %q", tree.RootNode().OriginalText())
	}
}

// TestPreprocess_TypeofCommentWithOpenParen locks in TF-02: a `(` inside a
// comment must not unbalance the scan and leave typeof unrewritten (which
// tree-sitter then silently mis-parses as a call). The comment is skipped and
// the rewrite still happens.
func TestPreprocess_TypeofCommentWithOpenParen(t *testing.T) {
	source := []byte("int f(void){ typeof(int /* x ( y */) v = 0; return v; }\n")
	out, rewrites := preprocessGccExtensions(source)
	tree, _ := NewParser().Parse(source, "comment_open_paren.c")
	defer tree.Close()

	if len(rewrites) != 1 {
		t.Fatalf("expected 1 rewrite, got %d (rewritten: %q)", len(rewrites), string(out))
	}
	if tree.HasError() {
		t.Errorf("HasError() = true, want false; rewritten: %q", string(out))
	}
	if strings.Contains(string(out), "typeof") {
		t.Errorf("typeof was not rewritten: %q", string(out))
	}
}

// TestPreprocess_TypeofStringParen locks in TF-02's string form: a `(` inside a
// string literal must not unbalance the scan either.
func TestPreprocess_TypeofStringParen(t *testing.T) {
	source := []byte("int f(void){ typeof(\"(\") v = 0; return v; }\n")
	out, rewrites := preprocessGccExtensions(source)
	tree, _ := NewParser().Parse(source, "string_paren.c")
	defer tree.Close()

	if len(rewrites) != 1 {
		t.Fatalf("expected 1 rewrite, got %d (rewritten: %q)", len(rewrites), string(out))
	}
	if tree.HasError() {
		t.Errorf("HasError() = true, want false; rewritten: %q", string(out))
	}
	if strings.Contains(string(out), "typeof") {
		t.Errorf("typeof was not rewritten: %q", string(out))
	}
}

// TestPreprocess_SkipsPreprocessorDirectives locks in TF-03: a typeof(...) inside
// a `#define` body must be left byte-for-byte intact (rewriting it would delete
// the macro's parameter references), while a real typeof in code is still
// rewritten.
func TestPreprocess_SkipsPreprocessorDirectives(t *testing.T) {
	source := []byte(
		"#define SWAP_T(x) typeof(x)\n" +
			"int f(void){ typeof(int) v = 0; return v; }\n")
	out, rewrites := preprocessGccExtensions(source)
	got := string(out)

	if !strings.Contains(got, "#define SWAP_T(x) typeof(x)") {
		t.Errorf("macro body typeof was rewritten (should be preserved):\n got %q", got)
	}
	if len(rewrites) != 1 {
		t.Fatalf("expected exactly 1 rewrite (the code typeof), got %d: %q", len(rewrites), got)
	}
	if !strings.Contains(got, "void *") {
		t.Errorf("expected the code typeof to be rewritten, got %q", got)
	}
}

// TestPreprocess_UnterminatedStringDoesNotBlockLaterTypeof locks in TF-07: an
// unterminated string literal (a syntax error) must not make skipNonCode jump to
// EOF and suppress every later typeof rewrite on following lines.
func TestPreprocess_UnterminatedStringDoesNotBlockLaterTypeof(t *testing.T) {
	source := []byte("const char *s = \"unterminated\nint f(void){ typeof(int) v = 0; return v; }\n")
	_, rewrites := preprocessGccExtensions(source)
	if len(rewrites) != 1 {
		t.Errorf("expected 1 rewrite after unterminated string, got %d", len(rewrites))
	}
}

// TestNode_OriginalTextAndTypeofTypeSpecifier locks in the TF-04/TF-05 parser
// API: the tree records the typeof rewrite with its parameter, OriginalText
// returns the source as written (not the padded `void *`), and a declaration
// whose type was masked by a typeof rewrite is detected so detectors can treat
// its type as UNKNOWN.
func TestNode_OriginalTextAndTypeofTypeSpecifier(t *testing.T) {
	source := []byte("double ratio;\nint f(double ratio, int n){ typeof(ratio) d = ratio; return d / n; }\n")
	tree, _ := NewParser().Parse(source, "typeof_type.c")
	defer tree.Close()

	rws := tree.TypeofRewrites()
	if len(rws) != 1 || rws[0].Param != "ratio" {
		t.Fatalf("expected 1 rewrite with param %q, got %+v", "ratio", rws)
	}

	root := tree.RootNode()
	typeofDecls := 0
	for _, d := range root.FindAll("declaration") {
		if !d.TypeofTypeSpecifier() {
			continue
		}
		typeofDecls++
		if got := d.OriginalText(); !strings.Contains(got, "typeof(ratio)") {
			t.Errorf("OriginalText should show the original typeof, got %q", got)
		}
		if strings.Contains(d.Text(), "typeof") {
			t.Errorf("Text() (rewritten form) should not contain typeof, got %q", d.Text())
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
