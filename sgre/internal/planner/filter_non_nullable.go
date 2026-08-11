package planner

import (
	"context"
)

type NonNullableFilter struct{}

func NewNonNullableFilter() *NonNullableFilter {
	return &NonNullableFilter{}
}

func (f *NonNullableFilter) Name() string { return "non_nullable_array_suppress" }

func (f *NonNullableFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	var result []Candidate
	for _, c := range candidates {
		if c.NonNullable {
			continue
		}
		result = append(result, c)
	}
	return result, nil
}
