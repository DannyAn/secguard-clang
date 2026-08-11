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
