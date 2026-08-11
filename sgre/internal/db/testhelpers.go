package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func NewTestStore(t *testing.T) Store {
	t.Helper()
	ctx := context.Background()
	db, err := OpenInMemory(ctx)
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	s := NewStore(db)
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func NewTempFileStore(t *testing.T) Store {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_sgre.db")
	db, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("failed to open temp file db: %v", err)
	}
	s := NewStore(db)
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func AssertTableExists(t *testing.T, s Store, tableName string) {
	t.Helper()
	ctx := context.Background()
	var name string
	err := s.DB().QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tableName).Scan(&name)
	if err != nil {
		t.Errorf("table %q does not exist: %v", tableName, err)
	}
}

func AssertFilePermissions(t *testing.T, dbPath string) {
	t.Helper()
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("failed to stat db file: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("expected file permissions 0600, got %o", mode)
	}
}
