package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrDatabaseLocked = fmt.Errorf("db: database is locked")

func Open(ctx context.Context, dbPath string) (*sql.DB, error) {
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("db: open: resolve path: %w", err)
	}

	_, statErr := os.Stat(absPath)

	// `_busy_timeout` is NOT a driver parameter — modernc.org/sqlite only applies
	// `_pragma` values. `busy_timeout(10000)` must ride the `_pragma` channel, or
	// SQLITE_BUSY returns immediately under parallel writers and the detectors'
	// InsertEvent errors are swallowed, silently dropping findings. The timeout
	// was raised from 5000ms to 10000ms so the multi-subagent concurrent write
	// storm (up to 8 parallel `secguard report --write-json` processes sharing
	// one WAL database) has a wider window before the application-layer retry in
	// UpsertFinding/InsertFinding engages.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", absPath)
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
	return strings.Contains(s, "database is locked") || strings.Contains(s, "SQLITE_BUSY")
}

// withBusyRetryID runs fn and retries on SQLITE_BUSY with exponential backoff
// (50ms → 100ms → 200ms …). Non-BUSY errors return immediately. maxRetries is
// the number of retries after the first attempt (3 → 4 total attempts). It is
// the application-layer companion to SQLite's busy_timeout pragma: busy_timeout
// handles brief lock contention inside the driver, while this loop handles the
// longer write-write serialization under the multi-subagent concurrent write
// storm. Returns the id from the successful attempt; on exhaustion returns a
// wrapped error so callers can distinguish BUSY-exhaustion from other failures.
func withBusyRetryID(ctx context.Context, maxRetries int, fn func() (int64, error)) (int64, error) {
	var lastErr error
	backoff := 50 * time.Millisecond
	for attempt := 0; attempt <= maxRetries; attempt++ {
		id, err := fn()
		if err == nil {
			return id, nil
		}
		lastErr = err
		if !isLockedErr(err) {
			return 0, err
		}
		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return 0, fmt.Errorf("db: busy retry exhausted after %d attempts: %w", maxRetries+1, lastErr)
}

func now() int64 {
	return time.Now().Unix()
}

// chunkIDs splits ids into chunks of at most maxChunk elements so a SQL
// `IN (...)` clause never exceeds SQLite's bind-variable limit. It is used by the
// batched List*ByIDs methods to replace per-ID point queries with a few chunked
// queries.
func chunkIDs(ids []int64, maxChunk int) [][]int64 {
	var chunks [][]int64
	for len(ids) > 0 {
		n := len(ids)
		if n > maxChunk {
			n = maxChunk
		}
		chunks = append(chunks, ids[:n])
		ids = ids[n:]
	}
	return chunks
}
