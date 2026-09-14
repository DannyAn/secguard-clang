//go:build !nosqlite

package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestWithImmediateTx_Commits proves the basic contract: writes inside the tx
// commit and are visible after.
func TestWithImmediateTx_Commits(t *testing.T) {
	s := NewTestStore(t)
	ctx := context.Background()

	if err := s.WithImmediateTx(ctx, func(tx Store) error {
		if _, err := tx.InsertFile(ctx, &File{Path: "/a.c", Language: "c", Checksum: "x", LOC: 1}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("WithImmediateTx failed: %v", err)
	}

	files, err := s.ListFiles(ctx)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Path != "/a.c" {
		t.Fatalf("expected 1 committed file /a.c, got %+v", files)
	}
}

// TestWithImmediateTx_AcquiresLockUpfront proves the fix's core property: BEGIN
// IMMEDIATE takes the SQLite write lock at BEGIN, so a contended batch blocks
// for a single busy_timeout and then fails with a clean "database is locked" —
// instead of the deferred-transaction behavior where each row re-waits the
// busy_timeout + app-layer retry and a batch scales that by its row count (the
// multi-minute "persist hangs" production failure).
func TestWithImmediateTx_AcquiresLockUpfront(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "t.db")
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(500)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath)

	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	if err := InitSchema(context.Background(), sdb); err != nil {
		t.Fatal(err)
	}

	// A second connection holds the write lock for the duration of the test.
	holder, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	htx, err := holder.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := htx.Exec("CREATE TABLE IF NOT EXISTS _lockprobe (id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	defer htx.Rollback()

	s := NewStore(sdb)
	start := time.Now()
	err = s.WithImmediateTx(context.Background(), func(tx Store) error {
		t.Error("fn must not run: BEGIN IMMEDIATE should have blocked/failed on the held lock")
		return nil
	})
	elapsed := time.Since(start)

	if err == nil || !isLockedErr(err) {
		t.Fatalf("expected a locked error, got %v (elapsed %v)", err, elapsed)
	}
	if elapsed < 400*time.Millisecond {
		t.Errorf("expected BEGIN IMMEDIATE to block ~busy_timeout(500ms) before failing, elapsed %v", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("expected a bounded (single busy_timeout) failure, elapsed %v", elapsed)
	}
}
