//go:build !nosqlite

package graph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// indexTwoFiles writes each source to its own .c file, indexes the functions,
// and returns the store, parser, and the function IDs keyed by file index and
// name.
func indexTwoFiles(t *testing.T, srcs ...string) (db.Store, *parser.Parser, map[string]int64) {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	p := parser.NewParser()
	t.Cleanup(func() { p.CloseAll() })
	ids := map[string]int64{}
	dir := t.TempDir()
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
			id, err := store.InsertFunction(ctx, &db.Function{
				FileID: fileID, Name: name, StartLine: def.StartLine(), EndLine: def.EndLine(),
			})
			if err != nil {
				t.Fatal(err)
			}
			ids[fmt.Sprintf("%d:%s", i, name)] = id
		}
		tree.Close()
	}
	return store, p, ids
}

// TestBuildInterproceduralAlias_SameNameStaticFunctions pins the multi-value
// name index: two translation units each define a `static` function with the
// SAME name, and a caller in the second unit must return-alias to BOTH return
// sources. The old single-value name map kept only one and silently severed the
// other's cross-function alias edges.
func TestBuildInterproceduralAlias_SameNameStaticFunctions(t *testing.T) {
	store, p, ids := indexTwoFiles(t,
		`static void *make(void) { void *a = 0; return a; }`,
		`static void *make(void) { void *b = 0; return b; }
		 void *caller(void) { void *q = make(); return q; }`,
	)
	ctx := context.Background()
	g, err := BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}
	callerID := ids["1:caller"]
	if k := g.EdgeKind(AliasKey{FunctionID: callerID, Name: "q"}, AliasKey{FunctionID: ids["0:make"], Name: "a"}); k != AliasEdgeReturn {
		t.Errorf("caller.q ↔ make.a must be a return alias, got %v", k)
	}
	if k := g.EdgeKind(AliasKey{FunctionID: callerID, Name: "q"}, AliasKey{FunctionID: ids["1:make"], Name: "b"}); k != AliasEdgeReturn {
		t.Errorf("caller.q ↔ make.b must be a return alias, got %v", k)
	}
}

// TestBuildInterproceduralAlias_ReleaseFunctionDanglingReturn pins that a
// release function OTHER than free (kfree) marks a return source dangling, so
// `kfree(p); return p;` is a cross-function double-free gate, matching the
// ownership layer's releaseFunctions table.
func TestBuildInterproceduralAlias_ReleaseFunctionDanglingReturn(t *testing.T) {
	store, p, ids := indexTwoFiles(t,
		`void *kfree(void *);
		 void *make(void) { void *p = 0; kfree(p); return p; }
		 void *caller(void) { void *q = make(); return q; }`,
	)
	ctx := context.Background()
	g, err := BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}
	if k := g.EdgeKind(AliasKey{FunctionID: ids["0:caller"], Name: "q"}, AliasKey{FunctionID: ids["0:make"], Name: "p"}); k != AliasEdgeReturnDangling {
		t.Errorf("caller.q ↔ make.p must be a dangling return alias (kfree), got %v", k)
	}
}

// TestBuildInterproceduralAlias_CompoundAssignmentNotAliased pins that a
// compound assignment (`q += p`) is NOT read as a direct alias (`q = p`).
func TestBuildInterproceduralAlias_CompoundAssignmentNotAliased(t *testing.T) {
	store, p, ids := indexTwoFiles(t,
		`void f(void) { int *p = 0; int *q = 0; q += p; }`,
	)
	ctx := context.Background()
	g, err := BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}
	fnID := ids["0:f"]
	for _, k := range g.AliasesOf(AliasKey{FunctionID: fnID, Name: "q"}) {
		if k.Name == "p" && k.FunctionID == fnID {
			t.Fatalf("q += p must not alias q to p")
		}
	}
}

// TestInterprocBuilder_CompoundAssignmentNoReturnEdge pins that `x += f()` does
// NOT emit a RETURN edge (x = x + f(), not x = f()).
func TestInterprocBuilder_CompoundAssignmentNoReturnEdge(t *testing.T) {
	store, p := indexSource(t, `
int helper(void) { return 5; }
void f(void) {
    int x = 0;
    x += helper();
}
`)
	ctx := context.Background()
	b := NewInterprocBuilder(store, p, nil)
	if _, err := b.Build(ctx); err != nil {
		t.Fatal(err)
	}
	returns, _ := store.ListGraphEdgesByType(ctx, "RETURN")
	if len(returns) != 0 {
		t.Errorf("compound assignment x += helper() must not emit a RETURN edge, got %d", len(returns))
	}
}
