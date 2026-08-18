package graph

import (
	"context"
	"encoding/json"
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
