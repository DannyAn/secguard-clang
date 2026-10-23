//go:build !nosqlite

package planner

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestStmtCFGSharedAcrossFilters pins the Phase-1 contract: when several
// filters analyze the SAME function in one scan, its statement CFG is built
// at most once and shared across all consumers via the Planner's CFGCache.
// Without the cache each filter rebuilds the CFG independently (the 8-12x
// waste identified in the architecture review).
func TestStmtCFGSharedAcrossFilters(t *testing.T) {
	src := []byte(`
int g;
int *get_null(void) { return (void*)0; }
int target(int *p) {
    int *q = get_null();
    int a = g / (g - g);
    if (p) { g = *p; }
    return a;
}
`)
	store := db.NewTestStore(t)
	p := parser.NewParser()
	defer p.CloseAll()

	// Register the function in the DB so fn.ID > 0 (the cache bypasses
	// non-positive IDs).
	fid := insertTestFunction(t, store, "target", "x.c", 3, 7)

	cache := graph.NewCFGCache()

	// Parse the tree once, hand the SAME body node to both consumers (the
	// production pipeline also shares one parse tree per file).
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
			// We want the body of `target`, not `get_null`; disambiguate by
			// the source line of the enclosing function.
			for p := n.Parent(); p != nil; p = p.Parent() {
				if p.Kind() == "function_definition" {
					// Locate the function name via the declarator.
					decl := p.ChildByFieldName("declarator")
					if decl != nil {
						// Cheap text sniff is enough for a fixture this small.
						if decl.Text() == "target(int *p)" {
							body = n
							found = true
						}
					}
					break
				}
			}
			return
		}
		for _, c := range n.Children() {
			walk(c)
		}
	}
	walk(root)
	if !found {
		t.Fatal("target body not found")
	}

	fn := &db.Function{ID: fid, Name: "target", FileID: 1, StartLine: 3, EndLine: 7}

	// Simulate two filter-style consumers hitting the same function through
	// the same cache.
	cfgA := graph.BuildStmtCFGWithCache(cache, fn.ID, body, fn.EndLine)
	cfgB := graph.BuildStmtCFGWithCache(cache, fn.ID, body, fn.EndLine)
	if cfgA != cfgB {
		t.Fatalf("cache did not share CFG: cfgA=%p cfgB=%p", cfgA, cfgB)
	}
	builds, hits := cache.Stats()
	if builds != 1 || hits != 1 {
		t.Fatalf("stats: builds=%d hits=%d, want 1/1", builds, hits)
	}

	// A null cache reproduces the legacy behavior (every call rebuilds).
	cfgC := graph.BuildStmtCFGWithCache(nil, fn.ID, body, fn.EndLine)
	cfgD := graph.BuildStmtCFGWithCache(nil, fn.ID, body, fn.EndLine)
	if cfgC == cfgD {
		t.Fatal("nil cache unexpectedly returned the same *StmtCFG pointer")
	}
	_ = context.Background()
}

// insertTestFunction inserts a minimal function row and returns its ID.
func insertTestFunction(t *testing.T, store db.Store, name, path string, start, end int) int64 {
	t.Helper()
	fileID, err := store.InsertFile(context.Background(), &db.File{Path: path, Checksum: "x", LOC: 10})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	fnID, err := store.InsertFunction(context.Background(), &db.Function{
		FileID: fileID, Name: name, Signature: "int " + name + "(void)",
		StartLine: start, EndLine: end,
	})
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}
	return fnID
}
