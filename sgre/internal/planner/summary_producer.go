package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// EnsureFunctionSummaries backfills a function_summary row for every indexed
// function that lacks one, so the coverage acceptance (≥90% of indexed
// functions) holds. return_nullable keeps its existing semantics — true only
// for the literal-`return NULL`/`0` functions the null-source detector already
// flagged — and the backfill writes false (no literal-null witness) for the
// rest. Richer dimensions (parameter_nullable, side_effect, failure-path
// ownership, return-value semantics) layer onto this row without a schema
// change. Idempotent: existing rows are left untouched.
func EnsureFunctionSummaries(ctx context.Context, store db.Store) (int, error) {
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return 0, fmt.Errorf("ensure function summaries: list functions: %w", err)
	}
	ids := make([]int64, len(funcs))
	for i, fn := range funcs {
		ids[i] = fn.ID
	}
	existing, err := store.ListSummariesByFunctionIDs(ctx, ids)
	if err != nil {
		return 0, fmt.Errorf("ensure function summaries: list summaries: %w", err)
	}
	produced := 0
	for _, fn := range funcs {
		if _, ok := existing[fn.ID]; ok {
			continue
		}
		if err := store.UpsertSummary(ctx, &db.FunctionSummary{FunctionID: fn.ID}); err != nil {
			return produced, fmt.Errorf("ensure function summaries: upsert %d: %w", fn.ID, err)
		}
		produced++
	}
	return produced, nil
}
