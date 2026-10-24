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

// TestAliasGraphEdgeKind pins the edge-provenance contract: the builder tags
// each alias edge with its provenance (local / return / param / global) so
// consumers can distinguish how an alias was formed. (A cross-function
// double-free consumer would gate on return-alias only — but the graph is
// call-site-insensitive, so that gating alone is not sound enough to enable
// it; see evidence/double_free.go.)
func TestAliasGraphEdgeKind(t *testing.T) {
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

	callerID := fnIDs["caller"]
	makePtrID := fnIDs["make_ptr"]
	usePtrID := fnIDs["use_ptr"]

	// caller.q ↔ make_ptr.p is a RETURN alias.
	if g.EdgeKind(AliasKey{FunctionID: callerID, Name: "q"}, AliasKey{FunctionID: makePtrID, Name: "p"}) != AliasEdgeReturn {
		t.Error("caller.q ↔ make_ptr.p must be AliasEdgeReturn")
	}
	// caller.q ↔ use_ptr.x is a PARAM alias.
	if g.EdgeKind(AliasKey{FunctionID: callerID, Name: "q"}, AliasKey{FunctionID: usePtrID, Name: "x"}) != AliasEdgeParam {
		t.Error("caller.q ↔ use_ptr.x must be AliasEdgeParam")
	}
	// AliasesOfKind with AliasEdgeReturn only reaches make_ptr.p.
	retSet := g.AliasesOfKind(AliasKey{FunctionID: callerID, Name: "q"}, AliasEdgeReturn)
	names := map[string]bool{}
	for _, k := range retSet {
		names[k.Name] = true
	}
	if !names["q"] || !names["p"] || names["x"] {
		t.Errorf("AliasesOfKind(caller.q, Return) = %v, want {q, p} (no x)", names)
	}
	// AliasesOfKind with AliasEdgeParam only reaches use_ptr.x.
	paramSet := g.AliasesOfKind(AliasKey{FunctionID: callerID, Name: "q"}, AliasEdgeParam)
	names = map[string]bool{}
	for _, k := range paramSet {
		names[k.Name] = true
	}
	if !names["q"] || !names["x"] || names["p"] {
		t.Errorf("AliasesOfKind(caller.q, Param) = %v, want {q, x} (no p)", names)
	}
}

// TestAliasGraph_DanglingReturnEdge pins the dangling-return gate: a callee
// that UNCONDITIONALLY frees its return source (`free(p); return p;`) tags the
// return-alias edge AliasEdgeReturnDangling, while a callee that frees only on
// an error path (conditional free) tags it plain AliasEdgeReturn. The
// cross-function double-free aggregation follows only the dangling kind.
func TestAliasGraph_DanglingReturnEdge(t *testing.T) {
	src := []byte(`
void *malloc(long);
void free(void *);
void *make_dangling(void) {
    void *p = malloc(16);
    free(p);
    return p;
}
void *make_live(int fail) {
    void *q = malloc(16);
    if (fail) {
        free(q);
        return 0;
    }
    return q;
}
void caller(void) {
    void *a = make_dangling();
    void *b = make_live(0);
    (void)a; (void)b;
}
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	store := db.NewTestStore(t)
	ctx := context.Background()
	fileID, err := store.InsertFile(ctx, &db.File{Path: path, Checksum: "x", LOC: 25})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	fnIDs := map[string]int64{}
	for _, fn := range []struct {
		name  string
		start int
		end   int
	}{
		{"make_dangling", 4, 8},
		{"make_live", 9, 16},
		{"caller", 17, 21},
	} {
		id, err := store.InsertFunction(ctx, &db.Function{
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
	g, err := BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}

	// caller.a ↔ make_dangling.p is a DANGLING return (unconditional free).
	if k := g.EdgeKind(AliasKey{FunctionID: fnIDs["caller"], Name: "a"}, AliasKey{FunctionID: fnIDs["make_dangling"], Name: "p"}); k != AliasEdgeReturnDangling {
		t.Errorf("caller.a ↔ make_dangling.p = %v, want AliasEdgeReturnDangling", k)
	}
	// caller.b ↔ make_live.q is a LIVE return (conditional free only).
	if k := g.EdgeKind(AliasKey{FunctionID: fnIDs["caller"], Name: "b"}, AliasKey{FunctionID: fnIDs["make_live"], Name: "q"}); k != AliasEdgeReturn {
		t.Errorf("caller.b ↔ make_live.q = %v, want AliasEdgeReturn", k)
	}
}
