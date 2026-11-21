package db

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *store) InsertExpression(ctx context.Context, e *Expression) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO expressions (function_id, text, line, expr_type) VALUES (?, ?, ?, ?)`,
		e.FunctionID, e.Text, e.Line, e.ExprType)
	if err != nil {
		return 0, fmt.Errorf("db: insert expression: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert expression: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) ListExpressionsByFunction(ctx context.Context, functionID int64) ([]*Expression, error) {
	exprs, err := queryList(ctx, s.exec,
		`SELECT id, function_id, text, line, expr_type FROM expressions WHERE function_id = ? ORDER BY line`, []interface{}{functionID},
		func(rows *sql.Rows) (*Expression, error) {
			e := &Expression{}
			if err := rows.Scan(&e.ID, &e.FunctionID, &e.Text, &e.Line, &e.ExprType); err != nil {
				return nil, err
			}
			return e, nil
		})
	if err != nil {
		return nil, fmt.Errorf("db: list expressions by function: %w", err)
	}
	return exprs, nil
}
