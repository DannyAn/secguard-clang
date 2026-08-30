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
	bofEvents, err := f.store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		return nil, nil, fmt.Errorf("array oob precedence filter: %w", err)
	}

	// Batch-load every location both loops consult, so neither issues one point
	// query per row (an N+1 storm on codebases with tens of thousands of
	// BUFFER_ACCESS events).
	locIDs := make([]int64, 0, len(bofEvents)+len(candidates))
	seen := make(map[int64]bool, len(bofEvents)+len(candidates))
	for _, e := range bofEvents {
		if e.LocationID > 0 && !seen[e.LocationID] {
			seen[e.LocationID] = true
			locIDs = append(locIDs, e.LocationID)
		}
	}
	for _, c := range candidates {
		if c.LocationID > 0 && !seen[c.LocationID] {
			seen[c.LocationID] = true
			locIDs = append(locIDs, c.LocationID)
		}
	}
	locsByID, err := f.store.ListLocationsByIDs(ctx, locIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("array oob precedence filter: list locations: %w", err)
	}

	bofLocations := make(map[string]bool)
	for _, e := range bofEvents {
		if loc := locsByID[e.LocationID]; loc != nil {
			bofLocations[fmt.Sprintf("%d:%d", loc.FileID, loc.Line)] = true
		}
	}

	kept, dropped := partition(candidates,
		func(c Candidate) bool {
			if c.NonNullable && c.LocationID > 0 {
				if loc := locsByID[c.LocationID]; loc != nil {
					if bofLocations[fmt.Sprintf("%d:%d", loc.FileID, loc.Line)] {
						return false
					}
				}
			}
			return true
		},
		func(c Candidate) string {
			return "array out-of-bounds BUFFER_ACCESS already covers this location"
		},
		f.Name())
	return kept, dropped, nil
}
