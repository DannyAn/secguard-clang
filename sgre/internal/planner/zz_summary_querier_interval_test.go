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

// TestSummaryQuerierIntervalDimension pins the Phase-13 follow-up: SummaryOf
// resolves the Interval dimension via the return-statement interval join —
// literal returns contribute const intervals, identifier returns contribute
// the range flow's interval at the return line, and multiple returns join.
func TestSummaryQuerierIntervalDimension(t *testing.T) {
	src := []byte(`
int returns_zero(void) {
    return 0;
}
int returns_literal(void) {
    return 42;
}
int returns_range(void) {
    int d = 5;
    return d;
}
int returns_mixed(int n) {
    if (n > 0) {
        return 1;
    }
    return -1;
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
		{"returns_zero", 2, 4},
		{"returns_literal", 5, 7},
		{"returns_range", 8, 11},
		{"returns_mixed", 12, 17},
	} {
		if _, err := store.InsertFunction(context.Background(), &db.Function{
			FileID: fileID, Name: fn.name, Signature: "int " + fn.name + "(void)",
			StartLine: fn.start, EndLine: fn.end,
		}); err != nil {
			t.Fatalf("insert function %s: %v", fn.name, err)
		}
	}

	q := NewSummaryQuerier(store, p, graph.NewCFGCache(), nil)

	// returns_zero → [0,0].
	if s, _ := q.SummaryOf(context.Background(), "returns_zero"); s.Interval.Top || s.Interval.Lo != 0 || s.Interval.Hi != 0 {
		t.Errorf("returns_zero.Interval = %+v, want [0,0]", s.Interval)
	}
	// returns_literal → [42,42].
	if s, _ := q.SummaryOf(context.Background(), "returns_literal"); s.Interval.Top || s.Interval.Lo != 42 || s.Interval.Hi != 42 {
		t.Errorf("returns_literal.Interval = %+v, want [42,42]", s.Interval)
	}
	// returns_range → [5,5] (d = 5 is a const interval at the return line).
	if s, _ := q.SummaryOf(context.Background(), "returns_range"); s.Interval.Top || s.Interval.Lo != 5 || s.Interval.Hi != 5 {
		t.Errorf("returns_range.Interval = %+v, want [5,5]", s.Interval)
	}
	// returns_mixed → join of [1,1] and [-1,-1] = [-1,1].
	if s, _ := q.SummaryOf(context.Background(), "returns_mixed"); s.Interval.Top || s.Interval.Lo != -1 || s.Interval.Hi != 1 {
		t.Errorf("returns_mixed.Interval = %+v, want [-1,1]", s.Interval)
	}
	// A non-existent function → Top.
	if s, _ := q.SummaryOf(context.Background(), "nonexistent"); !s.Interval.Top {
		t.Errorf("nonexistent.Interval.Top = %v, want true", s.Interval.Top)
	}
}
