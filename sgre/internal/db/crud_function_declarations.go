package db

import (
	"context"
	"fmt"
)

func (s *store) InsertFunctionDeclaration(ctx context.Context, d *FunctionDeclaration) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`INSERT OR IGNORE INTO function_declarations (file_id, name, signature, return_type, start_line) VALUES (?, ?, ?, ?, ?)`,
		d.FileID, d.Name, d.Signature, d.ReturnType, d.StartLine)
	if err != nil {
		return 0, fmt.Errorf("db: insert function declaration: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert function declaration: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) ListFunctionDeclarations(ctx context.Context) ([]*FunctionDeclaration, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, file_id, name, signature, return_type, start_line FROM function_declarations ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("db: list function declarations: %w", err)
	}
	defer rows.Close()

	var declarations []*FunctionDeclaration
	for rows.Next() {
		d := &FunctionDeclaration{}
		if err := rows.Scan(&d.ID, &d.FileID, &d.Name, &d.Signature, &d.ReturnType, &d.StartLine); err != nil {
			return nil, fmt.Errorf("db: scan function declaration: %w", err)
		}
		declarations = append(declarations, d)
	}
	return declarations, rows.Err()
}

func (s *store) DeleteFunctionDeclarationsByFile(ctx context.Context, fileID int64) error {
	if _, err := s.exec.ExecContext(ctx, `DELETE FROM function_declarations WHERE file_id = ?`, fileID); err != nil {
		return fmt.Errorf("db: delete function declarations by file: %w", err)
	}
	return nil
}
