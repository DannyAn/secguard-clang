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

// TestQuerierIntervalAt pins the Phase-10 seam: Planner exposes a
// graph.Querier whose IntervalAt reuses the range-flow engine (through the
// shared CFG cache) and returns a tighter-than-top interval for a provably
// bounded variable, or Top for an unknown one.
func TestQuerierIntervalAt(t *testing.T) {
	src := []byte(`
int target(int n) {
    int d = 5;
    int r = n / d;
    return r;
}
`)
	// The querier reads fn's body via the on-disk file parse cache, so the
	// fixture must exist on the filesystem (unlike planner filter tests that
	// can inject bodies through in-memory maps).
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	store := db.NewTestStore(t)
	p := parser.NewParser()
	defer p.CloseAll()

	fid := insertTestFunction(t, store, "target", path, 2, 6)
	file, err := store.GetFileByPath(context.Background(), path)
	if err != nil || file == nil {
		t.Fatalf("lookup file: %v", err)
	}
	fn := &db.Function{ID: fid, Name: "target", FileID: file.ID, StartLine: 2, EndLine: 6}

	q := NewQuerier(store, p, graph.NewCFGCache())

	// d is a literal 5 — the interval must be [5,5], not top.
	iv, ok := q.IntervalAt(context.Background(), fn, "d", 4)
	if !ok {
		t.Fatalf("IntervalAt(d) returned top; want a tighter interval")
	}
	if iv.Lo != 5 || iv.Hi != 5 {
		t.Errorf("IntervalAt(d) = [%d,%d], want [5,5]", iv.Lo, iv.Hi)
	}

	// n is a parameter — no tighter-than-top fact.
	iv2, ok2 := q.IntervalAt(context.Background(), fn, "n", 4)
	if ok2 {
		t.Errorf("IntervalAt(n) unexpectedly produced a non-top interval: %+v", iv2)
	}
	if !iv2.Top {
		t.Errorf("IntervalAt(n).Top = %v, want true", iv2.Top)
	}
}

// TestQuerierNullSeam pins the conservative seam: MustNonNullAt / MayBeNullAt
// return TriUnknown until Phase 11 lands the must-non-null lattice. This is
// the honest answer (never a false yes/no that would let a caller upgrade a
// candidate on an unsound proof).
func TestQuerierNullSeam(t *testing.T) {
	q := NewQuerier(nil, nil, nil)
	fn := &db.Function{ID: 1, Name: "f"}
	if got := q.MustNonNullAt(context.Background(), fn, "p", 10); got != graph.TriUnknown {
		t.Errorf("MustNonNullAt = %v, want TriUnknown", got)
	}
	if got := q.MayBeNullAt(context.Background(), fn, "p", 10); got != graph.TriUnknown {
		t.Errorf("MayBeNullAt = %v, want TriUnknown", got)
	}
}
