package db

import (
	"context"
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
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, function_id, text, line, expr_type FROM expressions WHERE function_id = ? ORDER BY line`, functionID)
	if err != nil {
		return nil, fmt.Errorf("db: list expressions by function: %w", err)
	}
	defer rows.Close()
	var exprs []*Expression
	for rows.Next() {
		e := &Expression{}
		if err := rows.Scan(&e.ID, &e.FunctionID, &e.Text, &e.Line, &e.ExprType); err != nil {
			return nil, fmt.Errorf("db: scan expression: %w", err)
		}
		exprs = append(exprs, e)
	}
	return exprs, rows.Err()
}
