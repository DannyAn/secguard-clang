package db

import (
	"context"
	"database/sql"
	"fmt"
)

// ReplaceFuncPtrWrites atomically replaces the whole func_ptr_writes table (the
// FuncPtrWriteBuilder rebuilds it every scan; the DB is ephemeral). The
// delete-then-insert runs in one immediate transaction so a mid-batch insert
// failure rolls the whole replacement back instead of leaving a half-populated
// table (a torn table breaks the indirect CALL edges the next stage resolves).
func (s *store) ReplaceFuncPtrWrites(ctx context.Context, writes []FuncPtrWrite) error {
	return s.WithImmediateTx(ctx, func(tx Store) error {
		return tx.(*store).replaceFuncPtrWrites(ctx, writes)
	})
}

func (s *store) replaceFuncPtrWrites(ctx context.Context, writes []FuncPtrWrite) error {
	if _, err := s.exec.ExecContext(ctx, `DELETE FROM func_ptr_writes`); err != nil {
		return fmt.Errorf("db: delete func ptr writes: %w", err)
	}
	for _, w := range writes {
		if _, err := s.exec.ExecContext(ctx,
			`INSERT INTO func_ptr_writes (slot_name, type_name, target_name, file, line) VALUES (?, ?, ?, ?, ?)`,
			w.SlotName, w.TypeName, w.TargetName, w.File, w.Line); err != nil {
			return fmt.Errorf("db: insert func ptr write: %w", err)
		}
	}
	return nil
}

// ListFuncPtrWrites returns every function-pointer slot -> target wiring.
func (s *store) ListFuncPtrWrites(ctx context.Context) ([]FuncPtrWrite, error) {
	out, err := queryList(ctx, s.exec,
		`SELECT id, slot_name, type_name, target_name, file, line FROM func_ptr_writes`, nil,
		func(rows *sql.Rows) (FuncPtrWrite, error) {
			var w FuncPtrWrite
			var typeName *string
			var file *string
			if err := rows.Scan(&w.ID, &w.SlotName, &typeName, &w.TargetName, &file, &w.Line); err != nil {
				return FuncPtrWrite{}, err
			}
			if typeName != nil {
				w.TypeName = *typeName
			}
			if file != nil {
				w.File = *file
			}
			return w, nil
		})
	if err != nil {
		return nil, fmt.Errorf("db: list func ptr writes: %w", err)
	}
	return out, nil
}
