package db

import (
	"context"
	"fmt"
)

func (s *store) InsertFileScopeVariable(ctx context.Context, v *FileScopeVariable) (int64, error) {
	if v.StorageClass == "" {
		v.StorageClass = "extern"
	}
	// UPSERT keyed on (file_id, name): a C tentative definition
	// (`int g_tbl[4];`) followed by its real definition (`int g_tbl[4] = {0};`)
	// is ONE file-scope object, so the second declaration updates the first
	// instead of violating the UNIQUE constraint and aborting the whole file's
	// index (issue #206 A.8 — the previous plain INSERT dropped the file).
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO file_scope_variables (file_id, name, type, storage_class, declaration_line, is_pointer) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(file_id, name) DO UPDATE SET
		   type = excluded.type,
		   storage_class = excluded.storage_class,
		   declaration_line = excluded.declaration_line,
		   is_pointer = excluded.is_pointer`,
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
