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

// TestSummaryQuerierNullDimension pins the Phase-13 follow-up: SummaryOf
// resolves the Null dimension via the recursive return-statement descent —
// literal NULL → TriYes, every return provably non-null → TriNo, call to
// another named function → recurse with cycle guard.
func TestSummaryQuerierNullDimension(t *testing.T) {
	src := []byte(`
void *returns_null(void) {
    return 0;
}
void *returns_propagated(void) {
    return returns_null();
}
int returns_int(void) {
    return 42;
}
void *returns_string(void) {
    return "hello";
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

	fileID, err := store.InsertFile(context.Background(), &db.File{Path: path, Checksum: "x", LOC: 20})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	for _, fn := range []struct {
		name  string
		start int
		end   int
	}{
		{"returns_null", 2, 4},
		{"returns_propagated", 5, 7},
		{"returns_int", 8, 10},
		{"returns_string", 11, 13},
	} {
		if _, err := store.InsertFunction(context.Background(), &db.Function{
			FileID: fileID, Name: fn.name, Signature: "void *" + fn.name + "(void)",
			StartLine: fn.start, EndLine: fn.end,
		}); err != nil {
			t.Fatalf("insert function %s: %v", fn.name, err)
		}
	}

	q := NewSummaryQuerier(store, p, graph.NewCFGCache())

	// returns_null → TriYes (literal 0 return).
	if s, _ := q.SummaryOf(context.Background(), "returns_null"); s.Null != graph.TriYes {
		t.Errorf("returns_null.Null = %v, want TriYes", s.Null)
	}
	// returns_propagated → TriYes (recursive: returns_null is TriYes).
	if s, _ := q.SummaryOf(context.Background(), "returns_propagated"); s.Null != graph.TriYes {
		t.Errorf("returns_propagated.Null = %v, want TriYes (recursive)", s.Null)
	}
	// returns_int → TriNo (literal 42, provably non-null).
	if s, _ := q.SummaryOf(context.Background(), "returns_int"); s.Null != graph.TriNo {
		t.Errorf("returns_int.Null = %v, want TriNo", s.Null)
	}
	// returns_string → TriNo (string literal, provably non-null).
	if s, _ := q.SummaryOf(context.Background(), "returns_string"); s.Null != graph.TriNo {
		t.Errorf("returns_string.Null = %v, want TriNo", s.Null)
	}
	// A non-existent function → TriUnknown.
	if s, _ := q.SummaryOf(context.Background(), "nonexistent"); s.Null != graph.TriUnknown {
		t.Errorf("nonexistent.Null = %v, want TriUnknown", s.Null)
	}
	// Interval/Taint/Capacity stay at their "unknown" placeholders.
	s, _ := q.SummaryOf(context.Background(), "returns_null")
	if !s.Interval.Top || s.Taint != graph.TriUnknown || s.Capacity != -1 {
		t.Errorf("non-null dimensions must stay at unknown placeholders, got %+v", s)
	}
}
