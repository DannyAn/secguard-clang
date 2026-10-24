//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestQuerierTypeOf pins the Phase-11 follow-up: TypeOf resolves a plain
// declarator's type via graph.TypeByName, and reports ok=false for a
// typedef / unknown variable (the honest "cannot determine" answer).
func TestQuerierTypeOf(t *testing.T) {
	src := []byte(`
void target(void) {
    int i = 0;
    unsigned long ul = 1;
    size_t s = 2;
    double d = 3.0;
    void *p = (void*)0;
}
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	store := db.NewTestStore(t)
	p := parser.NewParser()
	defer p.CloseAll()

	fileID, err := store.InsertFile(context.Background(), &db.File{Path: path, Checksum: "x", LOC: 10})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	fnID, err := store.InsertFunction(context.Background(), &db.Function{
		FileID: fileID, Name: "target", Signature: "void target(void)",
		StartLine: 2, EndLine: 8,
	})
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}
	fn := &db.Function{ID: fnID, Name: "target", FileID: fileID, StartLine: 2, EndLine: 8}

	q := NewQuerier(store, p, graph.NewCFGCache())

	cases := []struct {
		name     string
		wantKind graph.TypeKind
		wantOK   bool
	}{
		{"i", graph.TypeInt, true},
		{"ul", graph.TypeUint, true},
		{"s", graph.TypeUint, true},
		{"d", graph.TypeFloat, true},
		{"p", graph.TypeUnknown, false}, // void * is not in the name table — ok=false
		{"nonexistent", graph.TypeUnknown, false},
	}
	for _, tc := range cases {
		ty, ok := q.TypeOf(context.Background(), fn, tc.name)
		if ok != tc.wantOK {
			t.Errorf("TypeOf(%q).ok = %v, want %v", tc.name, ok, tc.wantOK)
			continue
		}
		if ok && ty.Kind != tc.wantKind {
			t.Errorf("TypeOf(%q).Kind = %v, want %v", tc.name, ty.Kind, tc.wantKind)
		}
	}
}

// TestQuerierTypeOf_Parameter pins the parameter fallback: TypeOf resolves a
// function parameter's type from the function_definition's parameter_list,
// so `int n` in `void target(int n, unsigned long m)` returns Int32 for n
// and Uint64 for m.
func TestQuerierTypeOf_Parameter(t *testing.T) {
	src := []byte(`
void target(int n, unsigned long m, double d, void *p) {
    (void)n; (void)m; (void)d; (void)p;
}
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	store := db.NewTestStore(t)
	p := parser.NewParser()
	defer p.CloseAll()

	fileID, err := store.InsertFile(context.Background(), &db.File{Path: path, Checksum: "x", LOC: 5})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	fnID, err := store.InsertFunction(context.Background(), &db.Function{
		FileID: fileID, Name: "target", Signature: "void target(int n, unsigned long m, double d, void *p)",
		StartLine: 2, EndLine: 4,
	})
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}
	fn := &db.Function{ID: fnID, Name: "target", FileID: fileID, StartLine: 2, EndLine: 4}

	q := NewQuerier(store, p, graph.NewCFGCache())

	cases := []struct {
		name     string
		wantKind graph.TypeKind
		wantOK   bool
	}{
		{"n", graph.TypeInt, true},
		{"m", graph.TypeUint, true},
		{"d", graph.TypeFloat, true},
		{"p", graph.TypeUnknown, false}, // void * is not in the name table
	}
	for _, tc := range cases {
		ty, ok := q.TypeOf(context.Background(), fn, tc.name)
		if ok != tc.wantOK {
			t.Errorf("TypeOf(%q).ok = %v, want %v", tc.name, ok, tc.wantOK)
			continue
		}
		if ok && ty.Kind != tc.wantKind {
			t.Errorf("TypeOf(%q).Kind = %v, want %v", tc.name, ty.Kind, tc.wantKind)
		}
	}
}
