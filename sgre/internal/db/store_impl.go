package db

import (
	"context"
	"database/sql"
	"fmt"
)

type dbExec interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

type store struct {
	db   *sql.DB
	exec dbExec
}

func NewStore(db *sql.DB) Store {
	return &store{db: db, exec: db}
}

func (s *store) Close() error {
	return Close(s.db)
}

func (s *store) DB() *sql.DB {
	return s.db
}

func (s *store) WithTx(ctx context.Context, fn func(Store) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: with tx: begin: %w", err)
	}

	txStore := &store{db: s.db, exec: tx}
	err = fn(txStore)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("db: with tx: rollback failed after error: %v: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: with tx: commit: %w", err)
	}
	return nil
}

// WithImmediateTx acquires the SQLite write lock up front (BEGIN IMMEDIATE) and
// runs fn on the same connection, then COMMITs. A deferred transaction (the
// default WithTx) does not take the write lock until the first write statement,
// so under the multi-subagent concurrent write storm each row of a batch could
// independently wait busy_timeout and the app-layer retry — with busy_timeout
// 10s and 4 retry attempts, a single contended row costs ~40s and a whole batch
// scales that by its row count (the "persist hangs for an hour" production
// failure). BEGIN IMMEDIATE makes the lock acquisition happen exactly once, so
// the batch either serializes quickly or fails after one busy_timeout with a
// clean "database is locked" the caller can act on.
func (s *store) WithImmediateTx(ctx context.Context, fn func(Store) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("db: with immediate tx: conn: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("db: with immediate tx: begin: %w", err)
	}
	txStore := &store{db: s.db, exec: conn}
	if err := fn(txStore); err != nil {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		return fmt.Errorf("db: with immediate tx: commit: %w", err)
	}
	return nil
}
