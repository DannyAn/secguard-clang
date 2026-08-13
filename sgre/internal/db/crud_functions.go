package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) InsertFunction(ctx context.Context, f *Function) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO functions (file_id, name, signature, return_type, is_static, start_line, end_line) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		f.FileID, f.Name, f.Signature, f.ReturnType, f.IsStatic, f.StartLine, f.EndLine)
	if err != nil {
		return 0, fmt.Errorf("db: insert function: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert function: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) GetFunctionByID(ctx context.Context, id int64) (*Function, error) {
	f := &Function{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, file_id, name, signature, return_type, is_static, start_line, end_line FROM functions WHERE id = ?`, id).
		Scan(&f.ID, &f.FileID, &f.Name, &f.Signature, &f.ReturnType, &f.IsStatic, &f.StartLine, &f.EndLine)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get function by id: %w", err)
	}
	return f, nil
}

func (s *store) GetFunctionByName(ctx context.Context, name string) (*Function, error) {
	f := &Function{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, file_id, name, signature, return_type, is_static, start_line, end_line FROM functions WHERE name = ? LIMIT 1`, name).
		Scan(&f.ID, &f.FileID, &f.Name, &f.Signature, &f.ReturnType, &f.IsStatic, &f.StartLine, &f.EndLine)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get function by name: %w", err)
	}
	return f, nil
}

func (s *store) ListFunctionsByFile(ctx context.Context, fileID int64) ([]*Function, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, file_id, name, signature, return_type, is_static, start_line, end_line FROM functions WHERE file_id = ? ORDER BY start_line`, fileID)
	if err != nil {
		return nil, fmt.Errorf("db: list functions by file: %w", err)
	}
	defer rows.Close()
	return scanFunctions(rows)
}

func (s *store) ListFunctions(ctx context.Context) ([]*Function, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, file_id, name, signature, return_type, is_static, start_line, end_line FROM functions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: list functions: %w", err)
	}
	defer rows.Close()
	return scanFunctions(rows)
}

func (s *store) DeleteFunctionsByFile(ctx context.Context, fileID int64) error {
	_, err := s.exec.ExecContext(ctx, `DELETE FROM functions WHERE file_id = ?`, fileID)
	if err != nil {
		return fmt.Errorf("db: delete functions by file: %w", err)
	}
	return nil
}

func scanFunctions(rows *sql.Rows) ([]*Function, error) {
	var funcs []*Function
	for rows.Next() {
		f := &Function{}
		if err := rows.Scan(&f.ID, &f.FileID, &f.Name, &f.Signature, &f.ReturnType, &f.IsStatic, &f.StartLine, &f.EndLine); err != nil {
			return nil, fmt.Errorf("db: scan function: %w", err)
		}
		funcs = append(funcs, f)
	}
	return funcs, rows.Err()
}
