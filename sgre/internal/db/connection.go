package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrDatabaseLocked = fmt.Errorf("db: database is locked")

// OpenOptions are optional SQLite connection budgets. Zero leaves the SQLite
// default; positive values apply to every pooled connection through the DSN so
// a connection opened later does not silently revert to the default.
type OpenOptions struct {
	CacheSizeKB   int
	MmapSizeBytes int64
}

func Open(ctx context.Context, dbPath string) (*sql.DB, error) {
	return OpenWithOptions(ctx, dbPath, OpenOptions{})
}

func OpenWithOptions(ctx context.Context, dbPath string, opts OpenOptions) (*sql.DB, error) {
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
	// InsertEvent/InsertFinding/UpsertFinding engages.
	//
	// The DSN is built with url.URL so a path containing `?`, `#`, `%` or spaces
	// stays a literal path component instead of re-parsing the query string.
	u := &url.URL{Scheme: "file", Path: absPath}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	if opts.CacheSizeKB > 0 {
		q.Add("_pragma", fmt.Sprintf("cache_size(-%d)", opts.CacheSizeKB))
	}
	if opts.MmapSizeBytes > 0 {
		q.Add("_pragma", fmt.Sprintf("mmap_size(%d)", opts.MmapSizeBytes))
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
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

// OpenReadOnly opens the database read-only for `secguard db`. The read-only
// contract is enforced by SQLite itself at the ENGINE level via the URI
// `mode=ro` parameter, which opens the file with SQLITE_OPEN_READONLY: a
// connection that later runs `PRAGMA query_only=0` (directly or as the second
// statement of a multi-statement query) still cannot write, because the OS file
// descriptor is read-only. `_pragma=query_only(1)` remains as a second,
// belt-and-suspenders layer. The DSN is built with url.URL so a path containing
// `?`, `#`, `%` or spaces cannot change the URI semantics. It deliberately skips
// InitSchema (schema creation is a write and must not run here).
func OpenReadOnly(ctx context.Context, dbPath string) (*sql.DB, error) {
	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("db: open read-only: resolve path: %w", err)
	}

	u := &url.URL{Scheme: "file", Path: absPath}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(10000)")
	u.RawQuery = q.Encode()

	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("db: open read-only: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: open read-only: ping: %w", err)
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
