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

	needsInit := false
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		needsInit = true
	}

	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", absPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: open: ping: %w", err)
	}

	if needsInit {
		if err := InitSchema(ctx, db); err != nil {
			db.Close()
			return nil, fmt.Errorf("db: open: init schema: %w", err)
		}
		if err := os.Chmod(absPath, 0600); err != nil {
			db.Close()
			return nil, fmt.Errorf("db: open: chmod: %w", err)
		}
	} else {
		if err := migrateSchema(ctx, db); err != nil {
			db.Close()
			return nil, fmt.Errorf("db: open: migrate schema: %w", err)
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
