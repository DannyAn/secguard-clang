package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) InsertType(ctx context.Context, ty *Type) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO types (name, kind) VALUES (?, ?)`, ty.Name, ty.Kind)
	if err != nil {
		return 0, fmt.Errorf("db: insert type: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert type: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) GetTypeByName(ctx context.Context, name string) (*Type, error) {
	ty := &Type{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, name, kind FROM types WHERE name = ? LIMIT 1`, name).
		Scan(&ty.ID, &ty.Name, &ty.Kind)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get type by name: %w", err)
	}
	return ty, nil
}

func (s *store) ListTypes(ctx context.Context) ([]*Type, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, name, kind FROM types ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: list types: %w", err)
	}
	defer rows.Close()
	var types []*Type
	for rows.Next() {
		ty := &Type{}
		if err := rows.Scan(&ty.ID, &ty.Name, &ty.Kind); err != nil {
			return nil, fmt.Errorf("db: scan type: %w", err)
		}
		types = append(types, ty)
	}
	return types, rows.Err()
}
