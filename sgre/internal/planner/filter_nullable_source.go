package planner

import (
	"context"
	"fmt"

	"github.com/kongan/secguard-lite/internal/db"
)

type NullableSourceFilter struct {
	store db.Store
}

func NewNullableSourceFilter(store db.Store) *NullableSourceFilter {
	return &NullableSourceFilter{store: store}
}

func (f *NullableSourceFilter) Name() string { return "nullable_source" }

func (f *NullableSourceFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	nullEvents, err := f.store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		return nil, fmt.Errorf("filter nullable source: %w", err)
	}
	nullFuncs := make(map[int64]bool)
	for _, e := range nullEvents {
		nullFuncs[e.EntityID] = true
	}

	var result []Candidate
	for _, c := range candidates {
		if c.NonNullable {
			continue
		}
		if nullFuncs[c.FunctionID] {
			c.HasNullableSource = true
			result = append(result, c)
		}
	}
	return result, nil
}
