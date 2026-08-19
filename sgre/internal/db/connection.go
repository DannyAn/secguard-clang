package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var ErrDatabaseLocked = fmt.Errorf("db: database is locked")

func Open(ctx context.Context, dbPath string) (*sql.DB, error) {
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("db: open: resolve path: %w", err)
	}

	_, statErr := os.Stat(absPath)

	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_busy_timeout=5000", absPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	db.SetMaxOpenConns(4)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: open: ping: %w", err)
	}

	if err := InitSchema(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: open: init schema: %w", err)
	}

	if os.IsNotExist(statErr) {
		if err := os.Chmod(absPath, 0600); err != nil {
			db.Close()
			return nil, fmt.Errorf("db: open: chmod: %w", err)
		}
	}

	return db, nil
}

func OpenInMemory(ctx context.Context) (*sql.DB, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("db: open in-memory: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: open in-memory: ping: %w", err)
	}

	if err := InitSchema(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: open in-memory: init schema: %w", err)
	}

	return db, nil
}

func Close(db *sql.DB) error {
	if db == nil {
		return nil
	}
	return db.Close()
}

func isLockedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "database is locked") || contains(s, "SQLITE_BUSY")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func now() int64 {
	return time.Now().Unix()
}
