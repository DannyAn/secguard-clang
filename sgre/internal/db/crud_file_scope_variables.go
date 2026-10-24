package db

import (
	"context"
	"fmt"
)

func (s *store) InsertFileScopeVariable(ctx context.Context, v *FileScopeVariable) (int64, error) {
	if v.StorageClass == "" {
		v.StorageClass = "extern"
	}
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO file_scope_variables (file_id, name, type, storage_class, declaration_line, is_pointer) VALUES (?, ?, ?, ?, ?, ?)`,
		v.FileID, v.Name, v.Type, v.StorageClass, v.DeclarationLine, v.IsPointer)
	if err != nil {
		return 0, fmt.Errorf("db: insert file scope variable: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert file scope variable: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) ListFileScopeVariables(ctx context.Context) ([]*FileScopeVariable, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, file_id, name, type, storage_class, declaration_line, is_pointer FROM file_scope_variables ORDER BY file_id, declaration_line`)
	if err != nil {
		return nil, fmt.Errorf("db: list file scope variables: %w", err)
	}
	defer rows.Close()
	var vars []*FileScopeVariable
	for rows.Next() {
		v := &FileScopeVariable{}
		if err := rows.Scan(&v.ID, &v.FileID, &v.Name, &v.Type, &v.StorageClass, &v.DeclarationLine, &v.IsPointer); err != nil {
			return nil, fmt.Errorf("db: scan file scope variable: %w", err)
		}
		vars = append(vars, v)
	}
	return vars, rows.Err()
}

func (s *store) DeleteFileScopeVariablesByFile(ctx context.Context, fileID int64) error {
	if _, err := s.exec.ExecContext(ctx, `DELETE FROM file_scope_variables WHERE file_id = ?`, fileID); err != nil {
		return fmt.Errorf("db: delete file scope variables by file: %w", err)
	}
	return nil
}
