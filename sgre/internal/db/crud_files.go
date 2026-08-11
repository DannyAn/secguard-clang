package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) InsertFile(ctx context.Context, f *File) (int64, error) {
	if f.Language == "" {
		f.Language = "c"
	}
	if f.CreatedAt == 0 {
		f.CreatedAt = now()
	}
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO files (path, language, checksum, loc, created_at) VALUES (?, ?, ?, ?, ?)`,
		f.Path, f.Language, f.Checksum, f.LOC, f.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("db: insert file: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert file: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) GetFileByID(ctx context.Context, id int64) (*File, error) {
	f := &File{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, path, language, checksum, loc, created_at FROM files WHERE id = ?`, id).
		Scan(&f.ID, &f.Path, &f.Language, &f.Checksum, &f.LOC, &f.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get file by id: %w", err)
	}
	return f, nil
}

func (s *store) GetFileByPath(ctx context.Context, path string) (*File, error) {
	f := &File{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, path, language, checksum, loc, created_at FROM files WHERE path = ?`, path).
		Scan(&f.ID, &f.Path, &f.Language, &f.Checksum, &f.LOC, &f.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get file by path: %w", err)
	}
	return f, nil
}

func (s *store) ListFiles(ctx context.Context) ([]*File, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, path, language, checksum, loc, created_at FROM files ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: list files: %w", err)
	}
	defer rows.Close()
	var files []*File
	for rows.Next() {
		f := &File{}
		if err := rows.Scan(&f.ID, &f.Path, &f.Language, &f.Checksum, &f.LOC, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: list files: scan: %w", err)
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

func (s *store) UpdateFileChecksum(ctx context.Context, id int64, checksum string, loc int) error {
	_, err := s.exec.ExecContext(ctx,
		`UPDATE files SET checksum = ?, loc = ? WHERE id = ?`, checksum, loc, id)
	if err != nil {
		return fmt.Errorf("db: update file checksum: %w", err)
	}
	return nil
}
