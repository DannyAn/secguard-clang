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

// TestBufferRangeFilter_ConfirmsOverflow pins the P0-1 contract: a
// secure_constraint_violation candidate whose SizeArgument interval provably
// exceeds its DstCapacity interval is upgraded to confirmed by the interval
// proof (the detector's lying-size heuristic becomes a machine proof).
func TestBufferRangeFilter_ConfirmsOverflow(t *testing.T) {
	src := []byte(`
void target(void) {
    char dst[4];
    strcpy_s(dst, 4, "hello");
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
		StartLine: 2, EndLine: 5,
	})
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}

	f := NewBufferRangeFilter(store, p, nil)
	f.SetCFGCache(graph.NewCFGCache())

	c := Candidate{
		FunctionID:   fnID,
		FunctionName: "target",
		FileID:       fileID,
		Line:         4,
		Category:     "secure_constraint_violation",
		SizeArgument: "6", // "hello" length including NUL
		DstCapacity:  "4",
	}

	kept, dropped, err := f.Apply(context.Background(), []Candidate{c})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected no dismissals, got %d", len(dropped))
	}
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept, got %d", len(kept))
	}
	if kept[0].SuspicionLevel != "confirmed" {
		t.Errorf("SuspicionLevel = %q, want confirmed (copy size 6 > dst capacity 4)", kept[0].SuspicionLevel)
	}
}

// TestBufferRangeFilter_DismissesSafe pins the inverse: a candidate whose
// SizeArgument interval is provably within its DstCapacity interval is
// dismissed (interval-proven safe).
func TestBufferRangeFilter_DismissesSafe(t *testing.T) {
	src := []byte(`
void target(void) {
    char dst[16];
    strcpy_s(dst, 16, "hi");
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
		StartLine: 2, EndLine: 5,
	})
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}

	f := NewBufferRangeFilter(store, p, nil)
	f.SetCFGCache(graph.NewCFGCache())

	c := Candidate{
		FunctionID:   fnID,
		FunctionName: "target",
		FileID:       fileID,
		Line:         4,
		Category:     "secure_constraint_violation",
		SizeArgument: "3", // "hi" length including NUL
		DstCapacity:  "16",
	}

	kept, dropped, err := f.Apply(context.Background(), []Candidate{c})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(kept) != 0 {
		t.Fatalf("expected 0 kept, got %d", len(kept))
	}
	if len(dropped) != 1 {
		t.Fatalf("expected 1 dismissed, got %d", len(dropped))
	}
}
