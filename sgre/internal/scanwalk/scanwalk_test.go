package scanwalk

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestEachParsesAndSkipsUnreadable(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "a.c")
	if err := os.WriteFile(good, []byte("int f(void) { return 0; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.c")

	p := parser.NewParser()
	t.Cleanup(p.CloseAll)
	logger := log.New(io.Discard, log.LevelWarn)

	visited := 0
	err := Each(context.Background(), p, logger, "test", []*db.File{
		{ID: 1, Path: good},
		{ID: 2, Path: missing},
	}, func(file *db.File, root parser.Node, tree *parser.Tree) {
		visited++
		if file.ID != 1 {
			t.Fatalf("visited unexpected file ID %d", file.ID)
		}
		if root.Kind() != "translation_unit" {
			t.Fatalf("root kind = %q", root.Kind())
		}
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if visited != 1 {
		t.Fatalf("visited %d files, want 1", visited)
	}
}

func TestEachStopsOnCanceledContext(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "a.c")
	if err := os.WriteFile(good, []byte("int f(void) { return 0; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p := parser.NewParser()
	t.Cleanup(p.CloseAll)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	visited := 0
	err := Each(ctx, p, log.New(io.Discard, log.LevelWarn), "test", []*db.File{{ID: 1, Path: good}},
		func(*db.File, parser.Node, *parser.Tree) { visited++ })
	if err != context.Canceled {
		t.Fatalf("Each error = %v, want context.Canceled", err)
	}
	if visited != 0 {
		t.Fatalf("visited %d files after cancel", visited)
	}
}
