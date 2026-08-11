package db

import (
	"context"
	"database/sql"
	"fmt"
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
	err := s.exec.QueryRowContext(ctx,
		`SELECT function_id, return_nullable, parameter_nullable, side_effect, summary_json FROM function_summary WHERE function_id = ?`, functionID).
		Scan(&sum.FunctionID, &sum.ReturnNullable, &sum.ParameterNullable, &sum.SideEffect, &sum.SummaryJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get summary by function: %w", err)
	}
	return sum, nil
}

func (s *store) UpdateReturnNullable(ctx context.Context, functionID int64, nullable bool) error {
	existing, _ := s.GetSummaryByFunction(ctx, functionID)
	sum := &FunctionSummary{FunctionID: functionID, ReturnNullable: nullable}
	if existing != nil {
		sum.ParameterNullable = existing.ParameterNullable
		sum.SideEffect = existing.SideEffect
		sum.SummaryJSON = existing.SummaryJSON
	}
	return s.UpsertSummary(ctx, sum)
}
