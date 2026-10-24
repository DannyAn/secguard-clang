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

// TestQuerierMayBeNullAt_RealFlow pins the Phase-10 follow-up: MayBeNullAt
// returns TriYes when a NULL_VALUE source provably reaches the line via the
// reaching-sources engine, and TriUnknown when no source is present. The
// fixture uses an explicit `p = NULL; return *p;` so the source is local and
// unambiguous.
func TestQuerierMayBeNullAt_RealFlow(t *testing.T) {
	src := []byte(`
int target(void) {
    int *p = 0;
    int x = *p;
    return x;
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

	// Insert file + function rows so the querier can locate the body.
	fileID, err := store.InsertFile(context.Background(), &db.File{Path: path, Checksum: "x", LOC: 10})
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	fnID, err := store.InsertFunction(context.Background(), &db.Function{
		FileID: fileID, Name: "target", Signature: "int target(void)",
		StartLine: 2, EndLine: 6,
	})
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}
	fn := &db.Function{ID: fnID, Name: "target", FileID: fileID, StartLine: 2, EndLine: 6}

	// Insert a NULL_VALUE event so buildNullModel picks it up as a source.
	locID, err := store.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 3, Column: 1})
	if err != nil {
		t.Fatalf("insert location: %v", err)
	}
	if _, err := store.InsertEvent(context.Background(), &db.SecurityEvent{
		EventType:  "NULL_VALUE",
		EntityID:   fnID,
		LocationID: locID,
		Properties: `{"variable":"p","origin":"literal_null","definite":"true"}`,
	}); err != nil {
		t.Fatalf("insert null-value event: %v", err)
	}

	q := NewQuerier(store, p, graph.NewCFGCache())

	// p at line 4 (the deref) — a NULL literal source reaches.
	if got := q.MayBeNullAt(context.Background(), fn, "p", 4); got != graph.TriYes {
		t.Errorf("MayBeNullAt(p, 4) = %v, want TriYes (NULL literal reaches)", got)
	}

	// MustNonNullAt must be TriNo (v is proven null).
	if got := q.MustNonNullAt(context.Background(), fn, "p", 4); got != graph.TriNo {
		t.Errorf("MustNonNullAt(p, 4) = %v, want TriNo (v is proven null)", got)
	}

	// An unrelated variable with no source → TriUnknown on both.
	if got := q.MayBeNullAt(context.Background(), fn, "q", 4); got != graph.TriUnknown {
		t.Errorf("MayBeNullAt(q, 4) = %v, want TriUnknown (no source)", got)
	}
	if got := q.MustNonNullAt(context.Background(), fn, "q", 4); got != graph.TriUnknown {
		t.Errorf("MustNonNullAt(q, 4) = %v, want TriUnknown (no must-non-null lattice yet)", got)
	}
}
