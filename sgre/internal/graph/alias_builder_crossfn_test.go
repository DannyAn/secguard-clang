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

// TestBuildInterproceduralAlias_StaticGlobalFileScoped pins the static-vs-extern
// distinction: a `static void *g` in two files is TWO objects (internal
// linkage, one per file), so `g = p` in file A and `g = q` in file B produce
// two DISTINCT global alias keys (FileID A vs FileID B) that do not merge.
func TestBuildInterproceduralAlias_StaticGlobalFileScoped(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	pathA := write("a.c", `
void *malloc(long);
static void *g;
void f1(void) { void *p = malloc(8); g = p; }
`)
	pathB := write("b.c", `
void *malloc(long);
static void *g;
void f2(void) { void *q = malloc(8); g = q; }
`)

	store := db.NewTestStore(t)
	ctx := context.Background()
	fa, _ := store.InsertFile(ctx, &db.File{Path: pathA, Checksum: "a", LOC: 10})
	fb, _ := store.InsertFile(ctx, &db.File{Path: pathB, Checksum: "b", LOC: 10})
	faFn, _ := store.InsertFunction(ctx, &db.Function{FileID: fa, Name: "f1", Signature: "void f1(void)", StartLine: 4, EndLine: 4})
	fbFn, _ := store.InsertFunction(ctx, &db.Function{FileID: fb, Name: "f2", Signature: "void f2(void)", StartLine: 4, EndLine: 4})
	store.InsertFileScopeVariable(ctx, &db.FileScopeVariable{FileID: fa, Name: "g", Type: "void", StorageClass: "static", DeclarationLine: 3, IsPointer: true})
	store.InsertFileScopeVariable(ctx, &db.FileScopeVariable{FileID: fb, Name: "g", Type: "void", StorageClass: "static", DeclarationLine: 3, IsPointer: true})

	p := parser.NewParser()
	defer p.CloseAll()
	g, err := BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}

	setA := g.AliasesOf(AliasKey{FunctionID: faFn, Name: "p"})
	var ga *AliasKey
	for _, k := range setA {
		if k.Name == "g" && k.FunctionID == 0 {
			ga = &k
		}
	}
	if ga == nil || ga.FileID != fa {
		t.Fatalf("f1.p must alias the file-A static global g (FileID=%d), got set %v", fa, setA)
	}

	setB := g.AliasesOf(AliasKey{FunctionID: fbFn, Name: "q"})
	for _, k := range setB {
		if k.Name == "g" && k.FunctionID == 0 && k.FileID == fa {
			t.Errorf("f2.q must NOT alias file-A's static global g (different file, different object); set %v", setB)
		}
	}
	// The two static globals must be distinct keys (different FileID), so the
	// closure of p never reaches q's global.
	for _, k := range setA {
		if k.FunctionID == 0 && k.Name == "g" && k.FileID == fb {
			t.Errorf("f1.p must not reach file-B's static global g")
		}
	}
}

// TestBuildInterproceduralAlias_UnknownLHSNotGlobal pins the symbol-table
// guard: a `typo_name = p` whose lhs is NOT a declared file-scope variable (and
// not a local) is NOT recorded as a global alias.
func TestBuildInterproceduralAlias_UnknownLHSNotGlobal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	src := []byte(`
void *malloc(long);
void f(void) {
    void *p = malloc(8);
    undefined_name = p;
}
`)
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	store := db.NewTestStore(t)
	ctx := context.Background()
	fileID, _ := store.InsertFile(ctx, &db.File{Path: path, Checksum: "x", LOC: 10})
	fnID, _ := store.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "f", Signature: "void f(void)", StartLine: 3, EndLine: 6})

	p := parser.NewParser()
	defer p.CloseAll()
	g, err := BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}
	set := g.AliasesOf(AliasKey{FunctionID: fnID, Name: "p"})
	for _, k := range set {
		if k.Name == "undefined_name" {
			t.Errorf("undefined_name must not be recorded as a global alias (not a declared file-scope name); set %v", set)
		}
	}
}

// TestBuildInterproceduralAlias_GlobalAlias pins the global-alias shape: a
// `g = p` whose g is a declared file-scope (extern) name is recorded with
// FunctionID=0 / FileID=0 (one object program-wide), so a global written in fn
// and read in another function shares the object with fn's p.
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
	// g_sink is a declared file-scope variable (extern by default): the global
	// alias is recorded only because the file-scope symbol table knows it.
	if _, err := store.InsertFileScopeVariable(context.Background(), &db.FileScopeVariable{
		FileID: fileID, Name: "g_sink", Type: "void", StorageClass: "extern", DeclarationLine: 4, IsPointer: true,
	}); err != nil {
		t.Fatalf("insert file-scope variable: %v", err)
	}

	p := parser.NewParser()
	defer p.CloseAll()

	g, err := BuildInterproceduralAlias(context.Background(), store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}

	// writer.p should alias the global g_sink (FunctionID=0, FileID=0).
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
