package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

type ArrayOOBPrecedenceFilter struct {
	store db.Store
}

func NewArrayOOBPrecedenceFilter(store db.Store) *ArrayOOBPrecedenceFilter {
	return &ArrayOOBPrecedenceFilter{store: store}
}

func (f *ArrayOOBPrecedenceFilter) Name() string { return "array_oob_precedence" }

func (f *ArrayOOBPrecedenceFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	// Only the non-nullable candidates can be suppressed (a nullable pointer
	// dereference is a null-deref, not an array OOB that BUFFER_ACCESS already
	// covers). Query the DB for exactly those locations instead of loading the
	// whole BUFFER_ACCESS event set: on a large tree that set is tens of
	// thousands of rows, and materializing it once per null-deref plan (the
	// biggest filter-chain memory spike) is the OOM trigger this fixes.
	locIDs := make([]int64, 0)
	seen := make(map[int64]bool)
	for _, c := range candidates {
		if c.NonNullable && c.LocationID > 0 && !seen[c.LocationID] {
			seen[c.LocationID] = true
			locIDs = append(locIDs, c.LocationID)
		}
	}
	if len(locIDs) == 0 {
		return candidates, nil, nil
	}

	covered, err := f.store.ListEventLocationIDsByType(ctx, "BUFFER_ACCESS", locIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("array oob precedence filter: %w", err)
	}

	kept, dropped := partition(candidates,
		func(c Candidate) bool {
			return !(c.NonNullable && c.LocationID > 0 && covered[c.LocationID])
		},
		func(c Candidate) string {
			return "array out-of-bounds BUFFER_ACCESS already covers this location"
		},
		f.Name())
	return kept, dropped, nil
}
