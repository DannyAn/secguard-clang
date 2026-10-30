package planner

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestEnsureFunctionSummaries(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	s.InsertFunction(ctx, &db.Function{Name: "a"}) // ID 1
	s.InsertFunction(ctx, &db.Function{Name: "b"}) // ID 2
	s.InsertFunction(ctx, &db.Function{Name: "c"}) // ID 3
	// The null-source detector already seeded a literal `return NULL` witness for
	// function 1; it must be left untouched by the backfill.
	s.summaries[1] = &db.FunctionSummary{FunctionID: 1, ReturnNullable: true}

	produced, err := EnsureFunctionSummaries(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if produced != 2 {
		t.Fatalf("produced = %d, want 2 (functions 2 and 3)", produced)
	}
	if s.summaries[2] == nil || s.summaries[3] == nil {
		t.Fatalf("backfill missed functions: %+v", s.summaries)
	}
	if s.summaries[2].ReturnNullable {
		t.Errorf("backfilled row must be return_nullable=false (no literal-null witness)")
	}
	if !s.summaries[1].ReturnNullable {
		t.Errorf("existing summary must be untouched: %+v", s.summaries[1])
	}

	// Idempotent: a second run produces nothing.
	again, err := EnsureFunctionSummaries(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Errorf("second run produced %d, want 0", again)
	}
}

func TestEnsureFunctionSummariesEmpty(t *testing.T) {
	ctx := context.Background()
	s := newMockStore()
	produced, err := EnsureFunctionSummaries(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if produced != 0 {
		t.Errorf("empty store produced %d, want 0", produced)
	}
}
