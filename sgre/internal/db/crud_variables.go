package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) InsertVariable(ctx context.Context, v *Variable) (int64, error) {
	if v.StorageClass == "" {
		v.StorageClass = "auto"
	}
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO variables (function_id, name, type, storage_class, declaration_line, is_pointer, is_nullable, source_kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.FunctionID, v.Name, v.Type, v.StorageClass, v.DeclarationLine, v.IsPointer, v.IsNullable, v.SourceKind)
	if err != nil {
		return 0, fmt.Errorf("db: insert variable: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert variable: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) GetVariableByID(ctx context.Context, id int64) (*Variable, error) {
	v := &Variable{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, function_id, name, type, storage_class, declaration_line, is_pointer, is_nullable, source_kind FROM variables WHERE id = ?`, id).
		Scan(&v.ID, &v.FunctionID, &v.Name, &v.Type, &v.StorageClass, &v.DeclarationLine, &v.IsPointer, &v.IsNullable, &v.SourceKind)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get variable by id: %w", err)
	}
	return v, nil
}

func (s *store) ListVariablesByFunction(ctx context.Context, functionID int64) ([]*Variable, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, function_id, name, type, storage_class, declaration_line, is_pointer, is_nullable, source_kind FROM variables WHERE function_id = ? ORDER BY declaration_line`, functionID)
	if err != nil {
		return nil, fmt.Errorf("db: list variables by function: %w", err)
	}
	defer rows.Close()
	var vars []*Variable
	for rows.Next() {
		v := &Variable{}
		if err := rows.Scan(&v.ID, &v.FunctionID, &v.Name, &v.Type, &v.StorageClass, &v.DeclarationLine, &v.IsPointer, &v.IsNullable, &v.SourceKind); err != nil {
			return nil, fmt.Errorf("db: scan variable: %w", err)
		}
		vars = append(vars, v)
	}
	return vars, rows.Err()
}

func (s *store) ListPointerVariables(ctx context.Context) ([]*Variable, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, function_id, name, type, storage_class, declaration_line, is_pointer, is_nullable, source_kind FROM variables WHERE is_pointer = 1 ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: list pointer variables: %w", err)
	}
	defer rows.Close()
	var vars []*Variable
	for rows.Next() {
		v := &Variable{}
		if err := rows.Scan(&v.ID, &v.FunctionID, &v.Name, &v.Type, &v.StorageClass, &v.DeclarationLine, &v.IsPointer, &v.IsNullable, &v.SourceKind); err != nil {
			return nil, fmt.Errorf("db: scan variable: %w", err)
		}
		vars = append(vars, v)
	}
	return vars, rows.Err()
}
