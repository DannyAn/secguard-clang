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

// TestBuildInterproceduralAlias_CrossFunction pins the Phase-12 follow-up:
// the builder wires return-alias (`q = foo()` links q to foo's `return p`)
// and parameter-alias (`foo(p)` links p to foo's formal parameter) edges
// across functions.
func TestBuildInterproceduralAlias_CrossFunction(t *testing.T) {
	src := []byte(`
void *malloc(long);
void free(void *);
void *make_ptr(void) {
    void *p = malloc(16);
    return p;
}
void use_ptr(void *x) {
    free(x);
}
void caller(void) {
    void *q = make_ptr();
    use_ptr(q);
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
	fns := []struct {
		name  string
		start int
		end   int
	}{
		{"make_ptr", 4, 7},
		{"use_ptr", 8, 10},
		{"caller", 11, 14},
	}
	fnIDs := map[string]int64{}
	for _, fn := range fns {
		id, err := store.InsertFunction(context.Background(), &db.Function{
			FileID: fileID, Name: fn.name, Signature: "void *" + fn.name + "(void)",
			StartLine: fn.start, EndLine: fn.end,
		})
		if err != nil {
			t.Fatalf("insert function %s: %v", fn.name, err)
		}
		fnIDs[fn.name] = id
	}

	p := parser.NewParser()
	defer p.CloseAll()

	g, err := BuildInterproceduralAlias(context.Background(), store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}

	// caller.q should alias make_ptr.p (return-alias) and use_ptr.x (parameter-alias).
	qKey := AliasKey{FunctionID: fnIDs["caller"], Name: "q"}
	set := g.AliasesOf(qKey)
	names := map[string]bool{}
	for _, k := range set {
		names[k.Name] = true
	}
	if !names["q"] || !names["p"] || !names["x"] {
		t.Errorf("caller.q alias set = %v, want {q, p, x} (return-alias + parameter-alias)", names)
	}
}

// TestBuildInterproceduralAlias_NoCycle pins the cycle guard: a recursive
// call graph must not loop forever in the alias closure.
func TestBuildInterproceduralAlias_NoCycle(t *testing.T) {
	src := []byte(`
void *f(void *a) {
    return a;
}
void *g(void *b) {
    return f(b);
}
void caller(void) {
    void *p = (void*)0;
    void *q = g(p);
    (void)q;
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
	for _, fn := range []struct {
		name  string
		start int
		end   int
	}{
		{"f", 2, 4},
		{"g", 5, 7},
		{"caller", 8, 12},
	} {
		if _, err := store.InsertFunction(context.Background(), &db.Function{
			FileID: fileID, Name: fn.name, Signature: "void *" + fn.name + "(void *)",
			StartLine: fn.start, EndLine: fn.end,
		}); err != nil {
			t.Fatalf("insert function %s: %v", fn.name, err)
		}
	}

	p := parser.NewParser()
	defer p.CloseAll()

	g, err := BuildInterproceduralAlias(context.Background(), store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}
	// Just assert the closure terminates and is non-empty.
	callerFn, _ := store.GetFunctionByName(context.Background(), "caller")
	set := g.AliasesOf(AliasKey{FunctionID: callerFn.ID, Name: "p"})
	if len(set) == 0 {
		t.Error("AliasesOf(p) returned empty set, want at least {p}")
	}
}

// TestBuildInterproceduralAlias_GlobalAlias pins the global-alias shape: a
// `g = p` whose g is NOT a local of fn is recorded with FunctionID=0 (a
// global / file-scope name), so a global written in fn and read in another
// function shares the object with fn's p.
func TestBuildInterproceduralAlias_GlobalAlias(t *testing.T) {
	src := []byte(`
void *malloc(long);
void free(void *);
void *g_sink;
void writer(void) {
    void *p = malloc(16);
    g_sink = p;
}
void reader(void) {
    free(g_sink);
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
	for _, fn := range []struct {
		name  string
		start int
		end   int
	}{
		{"writer", 5, 8},
		{"reader", 9, 11},
	} {
		if _, err := store.InsertFunction(context.Background(), &db.Function{
			FileID: fileID, Name: fn.name, Signature: "void " + fn.name + "(void)",
			StartLine: fn.start, EndLine: fn.end,
		}); err != nil {
			t.Fatalf("insert function %s: %v", fn.name, err)
		}
	}

	p := parser.NewParser()
	defer p.CloseAll()

	g, err := BuildInterproceduralAlias(context.Background(), store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}

	// writer.p should alias the global g_sink (FunctionID=0).
	writerFn, _ := store.GetFunctionByName(context.Background(), "writer")
	set := g.AliasesOf(AliasKey{FunctionID: writerFn.ID, Name: "p"})
	names := map[string]bool{}
	for _, k := range set {
		names[k.Name] = true
	}
	if !names["p"] || !names["g_sink"] {
		t.Errorf("writer.p alias set = %v, want {p, g_sink}", names)
	}
	// The global alias has FunctionID=0.
	found := false
	for _, k := range set {
		if k.Name == "g_sink" && k.FunctionID == 0 {
			found = true
		}
	}
	if !found {
		t.Error("g_sink alias must have FunctionID=0 (global)")
	}
}
