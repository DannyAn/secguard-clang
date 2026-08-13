package planner

import (
	"context"
)

type NonNullableFilter struct{}

func NewNonNullableFilter() *NonNullableFilter {
	return &NonNullableFilter{}
}

func (f *NonNullableFilter) Name() string { return "non_nullable_array_suppress" }

func (f *NonNullableFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	kept, dropped := partition(candidates,
		func(c Candidate) bool { return !c.NonNullable },
		func(c Candidate) string {
			return "variable is a non-nullable stack/global array or non-pointer"
		},
		f.Name())
	return kept, dropped, nil
}
