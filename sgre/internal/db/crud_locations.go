package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) InsertLocation(ctx context.Context, loc *Location) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO locations (file_id, line, column) VALUES (?, ?, ?)`,
		loc.FileID, loc.Line, loc.Column)
	if err != nil {
		return 0, fmt.Errorf("db: insert location: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert location: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) GetLocationByID(ctx context.Context, id int64) (*Location, error) {
	loc := &Location{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, file_id, line, column FROM locations WHERE id = ?`, id).
		Scan(&loc.ID, &loc.FileID, &loc.Line, &loc.Column)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get location by id: %w", err)
	}
	return loc, nil
}

func (s *store) ListLocationsByFile(ctx context.Context, fileID int64) ([]*Location, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, file_id, line, column FROM locations WHERE file_id = ? ORDER BY line`, fileID)
	if err != nil {
		return nil, fmt.Errorf("db: list locations by file: %w", err)
	}
	defer rows.Close()
	var locs []*Location
	for rows.Next() {
		loc := &Location{}
		if err := rows.Scan(&loc.ID, &loc.FileID, &loc.Line, &loc.Column); err != nil {
			return nil, fmt.Errorf("db: scan location: %w", err)
		}
		locs = append(locs, loc)
	}
	return locs, rows.Err()
}
