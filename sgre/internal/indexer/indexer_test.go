package indexer

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
)

func testLogger() *log.Logger {
	return log.New(nil, log.LevelError)
}

func TestIndexer_ExtractsAllFunctions(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()

	result, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "phase1", "sample.c"))
	if err != nil {
		t.Fatalf("Index failed: %v", err)
	}
	if result.FunctionsIndexed != 5 {
		t.Errorf("expected 5 functions indexed, got %d", result.FunctionsIndexed)
	}
}

func TestIndexer_StaticFlag(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()

	_, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "phase1", "sample.c"))
	if err != nil {
		t.Fatalf("Index failed: %v", err)
	}

	funcs, err := s.ListFunctions(ctx)
	if err != nil {
		t.Fatalf("ListFunctions failed: %v", err)
	}
	staticCount := 0
	for _, f := range funcs {
		if f.IsStatic {
			staticCount++
		}
	}
	if staticCount != 2 {
		t.Errorf("expected 2 static functions, got %d", staticCount)
	}
}

func TestIndexer_SkipsSyntaxErrors(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()

	result, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "phase1", "syntax_error.c"))
	if err != nil {
		t.Fatalf("Index failed: %v", err)
	}
	if result.FunctionsIndexed < 1 {
		t.Errorf("expected at least 1 function from syntax_error.c, got %d", result.FunctionsIndexed)
	}
}

func TestIndexer_FileForeignKey(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()

	_, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "phase1", "sample.c"))
	if err != nil {
		t.Fatalf("Index failed: %v", err)
	}

	funcs, err := s.ListFunctions(ctx)
	if err != nil {
		t.Fatalf("ListFunctions failed: %v", err)
	}
	for _, f := range funcs {
		file, _ := s.GetFileByID(ctx, f.FileID)
		if file == nil {
			t.Errorf("function %q references non-existent file_id %d", f.Name, f.FileID)
		}
	}
}

func TestIndexer_EmptyFile(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()

	result, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "phase1", "empty.c"))
	if err != nil {
		t.Fatalf("Index failed: %v", err)
	}
	if result.FunctionsIndexed != 0 {
		t.Errorf("expected 0 functions from empty.c, got %d", result.FunctionsIndexed)
	}
	if result.FilesIndexed != 1 {
		t.Errorf("expected 1 file indexed, got %d", result.FilesIndexed)
	}
}

func TestIndexer_NonexistentPath(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()

	_, err := idx.Index(ctx, "/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent path, got nil")
	}
}

func TestIndexer_IncrementalUpdate(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()
	path := filepath.Join("..", "..", "testdata", "phase1", "sample.c")

	_, err := idx.Index(ctx, path)
	if err != nil {
		t.Fatalf("first Index failed: %v", err)
	}

	files1, _ := s.ListFiles(ctx)
	result, err := idx.Index(ctx, path)
	if err != nil {
		t.Fatalf("second Index failed: %v", err)
	}

	files2, _ := s.ListFiles(ctx)
	if len(files1) != len(files2) {
		t.Errorf("file count changed on re-index: %d -> %d", len(files1), len(files2))
	}
	if result.FunctionsIndexed != 0 {
		t.Errorf("expected 0 new functions on unchanged re-index, got %d", result.FunctionsIndexed)
	}
}

func TestIndexer_FilesTablePopulated(t *testing.T) {
	s := db.NewTestStore(t)
	idx := NewIndexer(s, testLogger())
	ctx := context.Background()

	_, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "phase1", "sample.c"))
	if err != nil {
		t.Fatalf("Index failed: %v", err)
	}

	files, err := s.ListFiles(ctx)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least 1 file in files table")
	}
	if files[0].Language != "c" {
		t.Errorf("expected language 'c', got %q", files[0].Language)
	}
	if files[0].Checksum == "" {
		t.Error("expected non-empty checksum")
	}
	if files[0].LOC <= 0 {
		t.Error("expected positive LOC")
	}
}
