package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) GetMeta(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.exec.QueryRowContext(ctx,
		`SELECT value FROM pipeline_meta WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: get meta %q: %w", key, err)
	}
	return value, true, nil
}

func (s *store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO pipeline_meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	if err != nil {
		return fmt.Errorf("db: set meta %q: %w", key, err)
	}
	return nil
}
