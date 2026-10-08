package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func (s *store) UpsertSummary(ctx context.Context, sum *FunctionSummary) error {
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO function_summary (function_id, return_nullable, parameter_nullable, side_effect, summary_json)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(function_id) DO UPDATE SET
		   return_nullable = excluded.return_nullable,
		   parameter_nullable = excluded.parameter_nullable,
		   side_effect = excluded.side_effect,
		   summary_json = excluded.summary_json`,
		sum.FunctionID, sum.ReturnNullable, sum.ParameterNullable, sum.SideEffect, sum.SummaryJSON)
	if err != nil {
		return fmt.Errorf("db: upsert summary: %w", err)
	}
	return nil
}

func (s *store) GetSummaryByFunction(ctx context.Context, functionID int64) (*FunctionSummary, error) {
	sum := &FunctionSummary{}
	var parameterNullable, sideEffect, summaryJSON sql.NullString
	err := s.exec.QueryRowContext(ctx,
		`SELECT function_id, return_nullable, parameter_nullable, side_effect, summary_json FROM function_summary WHERE function_id = ?`, functionID).
		Scan(&sum.FunctionID, &sum.ReturnNullable, &parameterNullable, &sideEffect, &summaryJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get summary by function: %w", err)
	}
	sum.ParameterNullable = parameterNullable.String
	sum.SideEffect = sideEffect.String
	sum.SummaryJSON = summaryJSON.String
	return sum, nil
}

func (s *store) ListSummariesByFunctionIDs(ctx context.Context, functionIDs []int64) (map[int64]*FunctionSummary, error) {
	result := make(map[int64]*FunctionSummary, len(functionIDs))
	for _, chunk := range chunkIDs(functionIDs, 500) {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := s.exec.QueryContext(ctx,
			`SELECT function_id, return_nullable, parameter_nullable, side_effect, summary_json FROM function_summary WHERE function_id IN (`+placeholders+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("db: list summaries by function ids: %w", err)
		}
		for rows.Next() {
			sum := &FunctionSummary{}
			var parameterNullable, sideEffect, summaryJSON sql.NullString
			if scanErr := rows.Scan(&sum.FunctionID, &sum.ReturnNullable, &parameterNullable, &sideEffect, &summaryJSON); scanErr != nil {
				rows.Close()
				return nil, fmt.Errorf("db: scan summary: %w", scanErr)
			}
			sum.ParameterNullable = parameterNullable.String
			sum.SideEffect = sideEffect.String
			sum.SummaryJSON = summaryJSON.String
			result[sum.FunctionID] = sum
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("db: list summaries by function ids: %w", err)
		}
	}
	return result, nil
}

func (s *store) UpdateReturnNullable(ctx context.Context, functionID int64, nullable bool) error {
	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO function_summary (function_id, return_nullable)
		 VALUES (?, ?)
		 ON CONFLICT(function_id) DO UPDATE SET return_nullable = excluded.return_nullable`,
		functionID, nullable)
	if err != nil {
		return fmt.Errorf("db: update return nullable: %w", err)
	}
	return nil
}
