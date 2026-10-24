//go:build !nosqlite

package graph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestBuildInterproceduralAlias_LocalShapes pins the Phase-12 builder: the
// graph records the function-local alias shapes (init-declarator / plain
// assignment / cast alias / field alias / element address) the UAF /
// double-free / memory-leak detectors rely on, and ignores non-alias
// sources (arithmetic / call / literal).
func TestBuildInterproceduralAlias_LocalShapes(t *testing.T) {
	src := []byte(`
void *malloc(long);
void free(void *);
void target(void) {
    void *p = malloc(16);
    void *q = p;
    void *r = (void*)p;
    void *s = p + 1;
    int n = 42;
    free(q);
}
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	store := db.NewTestStore(t)
	fileID, err := store.InsertFile(context.Background(), &db.File{Path: path, Checksum: "x", LOC: 20})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	fnID, err := store.InsertFunction(context.Background(), &db.Function{
		FileID: fileID, Name: "target", Signature: "void target(void)",
		StartLine: 4, EndLine: 11,
	})
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}

	p := parser.NewParser()
	defer p.CloseAll()

	g, err := BuildInterproceduralAlias(context.Background(), store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}

	pKey := AliasKey{FunctionID: fnID, Name: "p"}
	set := g.AliasesOf(pKey)
	names := map[string]bool{}
	for _, k := range set {
		names[k.Name] = true
	}
	// p, q, r must be in one alias set (init + assign + cast).
	if !names["p"] || !names["q"] || !names["r"] {
		t.Errorf("alias set of p = %v, want {p,q,r}", names)
	}
	// s = p + 1 is arithmetic, NOT an alias.
	if names["s"] {
		t.Errorf("s (arithmetic) must not be in p's alias set: %v", names)
	}
	// n is a literal int, NOT an alias.
	if names["n"] {
		t.Errorf("n (literal) must not be in p's alias set: %v", names)
	}
}

// TestAliasSetViaQuerier documents the intended consumption shape: detectors
// call Querier.AliasSet instead of rebuilding findAliases per consumer.
// (The Querier.AliasSet implementation is Phase 12 follow-up; this test
// exercises the graph directly until the seam lands.)
func TestAliasSetViaQuerier(t *testing.T) {
	g := NewAliasGraph()
	p := AliasKey{FunctionID: 1, Name: "p"}
	q := AliasKey{FunctionID: 1, Name: "q"}
	g.Add(p, q)
	set := g.AliasesOf(p)
	if len(set) != 2 {
		t.Errorf("AliasesOf(p) = %v, want 2 members", set)
	}
}
