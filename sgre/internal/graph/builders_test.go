package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// indexSource writes src to a temp .c file, indexes it (file + one Function per
// function_definition), and returns a store + parser ready for a builder.
func indexSource(t *testing.T, src string) (db.Store, *parser.Parser) {
	t.Helper()
	store := db.NewTestStore(t)
	p := parser.NewParser()
	t.Cleanup(func() { p.CloseAll() })

	dir := t.TempDir()
	path := filepath.Join(dir, "t.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fileID, err := store.InsertFile(ctx, &db.File{Path: path, Language: "c"})
	if err != nil {
		t.Fatal(err)
	}

	tree, err := p.Parse([]byte(src), path)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	for _, def := range tree.RootNode().FindAll("function_definition") {
		name := testFunctionName(def)
		if name == "" {
			continue
		}
		if _, err := store.InsertFunction(ctx, &db.Function{
			FileID:    fileID,
			Name:      name,
			StartLine: def.StartLine(),
			EndLine:   def.EndLine(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return store, p
}

func testFunctionName(def parser.Node) string {
	for _, child := range def.NamedChildren() {
		if child.Kind() == "function_declarator" {
			for _, c := range child.NamedChildren() {
				if c.Kind() == "identifier" {
					return c.Text()
				}
			}
		}
		if child.Kind() == "pointer_declarator" {
			for _, gc := range child.NamedChildren() {
				if gc.Kind() == "function_declarator" {
					for _, c := range gc.NamedChildren() {
						if c.Kind() == "identifier" {
							return c.Text()
						}
					}
				}
			}
		}
	}
	return ""
}

// variableRefNames resolves variable_ref graph-node IDs to their variable names.
func variableRefNames(t *testing.T, store db.Store) map[int64]string {
	t.Helper()
	ctx := context.Background()
	nodes, err := store.ListGraphNodesByEntityType(ctx, "variable_ref")
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[int64]string, len(nodes))
	for _, n := range nodes {
		var props struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(n.Properties), &props); err != nil || props.Name == "" {
			continue
		}
		out[n.ID] = props.Name
	}
	return out
}

func TestAliasBuilder(t *testing.T) {
	store, p := indexSource(t, `
void f(void) {
    int *p = malloc(10);
    int *q = p;
    int *r;
    r = p->data;
    int *s;
    s = p;
    int *t = p->next;
}
`)
	ctx := context.Background()
	b := NewAliasBuilder(store, p, nil)
	res, err := b.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.EdgesCreated < 4 {
		t.Fatalf("expected >= 4 alias edges, got %d", res.EdgesCreated)
	}

	names := variableRefNames(t, store)
	edges, err := store.ListGraphEdgesByType(ctx, "ALIAS")
	if err != nil {
		t.Fatal(err)
	}
	// alias variable -> "base.field" ("" field = whole-variable alias)
	got := make(map[string]string)
	for _, e := range edges {
		var props struct {
			Field string `json:"field"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		got[names[e.SrcID]] = names[e.DstID] + "." + props.Field
	}

	want := map[string]string{
		"q": "p.",
		"r": "p.data",
		"s": "p.",
		"t": "p.next",
	}
	for alias, baseField := range want {
		if got[alias] != baseField {
			t.Errorf("alias %q: got %q, want %q", alias, got[alias], baseField)
		}
	}
}

func TestOwnershipBuilder(t *testing.T) {
	store, p := indexSource(t, `
void f(void) {
    int *p = malloc(10);
    free(p);
    g_slot = p;
}
int *g(void) {
    int *p = malloc(10);
    return p;
}
`)
	ctx := context.Background()
	b := NewOwnershipBuilder(store, p, nil)
	res, err := b.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.EdgesCreated < 3 {
		t.Fatalf("expected >= 3 ownership edges (1 release + 1 global transfer + 1 return transfer), got %d", res.EdgesCreated)
	}

	releases, _ := store.ListGraphEdgesByType(ctx, "RELEASE")
	if len(releases) != 1 {
		t.Errorf("expected 1 RELEASE edge (free(p)), got %d", len(releases))
	}

	transfers, _ := store.ListGraphEdgesByType(ctx, "OWNERSHIP_TRANSFER")
	if len(transfers) != 2 {
		t.Errorf("expected 2 OWNERSHIP_TRANSFER edges (global + return), got %d", len(transfers))
	}
	kinds := map[string]bool{}
	for _, e := range transfers {
		var props struct {
			Kind string `json:"kind"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		kinds[props.Kind] = true
	}
	if !kinds["global"] || !kinds["return"] {
		t.Errorf("expected both global and return transfer kinds, got %v", kinds)
	}
}

func TestInterprocBuilder(t *testing.T) {
	store, p := indexSource(t, `
int helper(int x) {
    return x + 1;
}
void f(void) {
    int a = 1;
    int b = helper(a);
}
`)
	ctx := context.Background()
	b := NewInterprocBuilder(store, p, nil)
	res, err := b.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.EdgesCreated < 2 {
		t.Fatalf("expected >= 2 interproc edges (param binding + return), got %d", res.EdgesCreated)
	}

	bindings, _ := store.ListGraphEdgesByType(ctx, "PARAM_BINDING")
	if len(bindings) != 1 {
		t.Errorf("expected 1 PARAM_BINDING edge (a -> helper.x), got %d", len(bindings))
	}
	if len(bindings) == 1 {
		var props struct {
			Callee string `json:"callee"`
			Index  int    `json:"index"`
		}
		json.Unmarshal([]byte(bindings[0].Properties), &props)
		if props.Callee != "helper" || props.Index != 0 {
			t.Errorf("PARAM_BINDING props = %+v, want callee=helper index=0", props)
		}
	}

	returns, _ := store.ListGraphEdgesByType(ctx, "RETURN")
	if len(returns) != 1 {
		t.Errorf("expected 1 RETURN edge (helper -> b), got %d", len(returns))
	}
}

// indexFiles writes each src to its own temp .c file, indexes them all into one
// store (in the given order, which becomes the ListFunctions iteration order),
// and returns the store + parser. Used to test cross-file graph behavior.
func indexFiles(t *testing.T, srcs ...string) (db.Store, *parser.Parser) {
	t.Helper()
	store := db.NewTestStore(t)
	p := parser.NewParser()
	t.Cleanup(func() { p.CloseAll() })

	dir := t.TempDir()
	ctx := context.Background()
	for i, src := range srcs {
		path := filepath.Join(dir, fmt.Sprintf("f%d.c", i))
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
		fileID, err := store.InsertFile(ctx, &db.File{Path: path, Language: "c"})
		if err != nil {
			t.Fatal(err)
		}
		tree, err := p.Parse([]byte(src), path)
		if err != nil {
			t.Fatal(err)
		}
		for _, def := range tree.RootNode().FindAll("function_definition") {
			name := testFunctionName(def)
			if name == "" {
				continue
			}
			if _, err := store.InsertFunction(ctx, &db.Function{
				FileID:    fileID,
				Name:      name,
				StartLine: def.StartLine(),
				EndLine:   def.EndLine(),
			}); err != nil {
				t.Fatal(err)
			}
		}
		tree.Close()
	}
	return store, p
}

// TestInterprocBuilderCrossFileForwardRef guards the two-phase PARAM_BINDING fix:
// a call site in an earlier file referencing a callee in a later file must still
// emit its PARAM_BINDING edge (the previous single-pass version missed it).
func TestInterprocBuilderCrossFileForwardRef(t *testing.T) {
	store, p := indexFiles(t,
		// f0.c (processed first): caller lives here.
		`void f(void) { int a = 1; int b = helper(a); }`,
		// f1.c (processed second): callee lives here.
		`int helper(int x) { return x + 1; }`,
	)
	ctx := context.Background()
	b := NewInterprocBuilder(store, p, nil)
	if _, err := b.Build(ctx); err != nil {
		t.Fatal(err)
	}

	bindings, err := store.ListGraphEdgesByType(ctx, "PARAM_BINDING")
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 PARAM_BINDING edge across files (a -> helper.x), got %d", len(bindings))
	}
}

// TestCallGraphSameNameDoesNotCollapse guards the same-name fix: two static
// functions with the same name in different files must both keep a CALL edge
// from their caller (a name->single-ID map would silently shadow one and, via
// call_reach, drop every candidate in the shadowed function).
func TestCallGraphSameNameDoesNotCollapse(t *testing.T) {
	store, p := indexFiles(t,
		`static void helper(void) {} void f(void) { helper(); }`,
		`static void helper(void) {} void g(void) { helper(); }`,
	)
	ctx := context.Background()
	b := NewCallGraphBuilder(store, p, nil)
	if _, err := b.Build(ctx); err != nil {
		t.Fatal(err)
	}

	// Resolve each function graph-node id to the Function it represents, then
	// assert both same-name static helpers are the destination of a CALL edge.
	fnNodeIDs := make(map[int64]int64)
	nodes, err := store.ListGraphNodesByEntityType(ctx, "function")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Properties == "" {
			fnNodeIDs[n.ID] = n.EntityID
		}
	}

	calls, err := store.ListGraphEdgesByType(ctx, "CALL")
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	helperCalled := 0
	for _, fn := range funcs {
		if fn.Name != "helper" {
			continue
		}
		for _, e := range calls {
			if fnNodeIDs[e.DstID] == fn.ID {
				helperCalled++
				break
			}
		}
	}
	if helperCalled != 2 {
		t.Fatalf("expected both same-name static helpers to keep a CALL edge, got %d/2", helperCalled)
	}
}

func TestAliasFromAssignSkipsNonAlias(t *testing.T) {
	p := parser.NewParser()
	defer p.CloseAll()
	tree, err := p.Parse([]byte(`void f(void) { int *q = malloc(10); }`), "t.c")
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	assigns := tree.RootNode().FindAll("init_declarator")
	if len(assigns) != 1 {
		t.Fatalf("expected 1 init_declarator, got %d", len(assigns))
	}
	if _, ok := aliasFromAssign(assigns[0]); ok {
		t.Error("malloc(10) RHS should not produce an alias edge")
	}
}
