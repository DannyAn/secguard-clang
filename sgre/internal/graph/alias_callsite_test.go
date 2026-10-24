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

// TestAliasGraph_CallSiteInsensitiveReturn pins the documented limitation that
// blocks a sound cross-function double-free aggregation: two calls to the SAME
// factory both return-alias to one AliasKey (the factory's return source), so a
// flow-insensitive graph cannot tell the two callers' objects apart. A consumer
// that collapses on return-alias alone would merge two DIFFERENT objects into a
// phantom "same object freed twice" (the allocator.c alloc_entry false positive).
//
// This is a characterization test: it documents the current behavior. When
// call-site sensitivity lands (one object per call), this test is updated —
// that update is the signal the cross-function double-free can be re-enabled.
func TestAliasGraph_CallSiteInsensitiveReturn(t *testing.T) {
	src := []byte(`
void *malloc(long);
void free(void *);
void *make(void) {
    void *p = malloc(16);
    return p;
}
void use1(void) {
    void *q1 = make();
    free(q1);
}
void use2(void) {
    void *q2 = make();
    free(q2);
}
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	store := db.NewTestStore(t)
	ctx := context.Background()
	fileID, err := store.InsertFile(ctx, &db.File{Path: path, Checksum: "x", LOC: 20})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	fnIDs := map[string]int64{}
	for _, fn := range []struct {
		name  string
		start int
		end   int
	}{
		{"make", 4, 7},
		{"use1", 8, 11},
		{"use2", 12, 15},
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

	// q1 and q2 are DIFFERENT objects (two make() calls), but the flow-
	// insensitive graph return-aliases both to the single make.p key, so their
	// alias sets overlap. That overlap is exactly what makes a return-alias
	// aggregation unsound: collapsing use1.free(q1) with use2.free(q2) would
	// merge two distinct allocations.
	hasMakeP := func(fnID int64, name string) bool {
		for _, k := range g.AliasesOf(AliasKey{FunctionID: fnID, Name: name}) {
			if k.FunctionID == fnIDs["make"] && k.Name == "p" {
				return true
			}
		}
		return false
	}
	if !hasMakeP(fnIDs["use1"], "q1") {
		t.Error("use1.q1 must return-alias to make.p")
	}
	if !hasMakeP(fnIDs["use2"], "q2") {
		t.Error("use2.q2 must return-alias to make.p")
	}
	// The documented limitation: q1 and q2 share the SAME return source key.
	if k := g.EdgeKind(AliasKey{FunctionID: fnIDs["use1"], Name: "q1"}, AliasKey{FunctionID: fnIDs["make"], Name: "p"}); k != AliasEdgeReturn {
		t.Errorf("q1 ↔ make.p must be a return alias, got %v", k)
	}
}
