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
	// covers). Resolve just those candidate locations (bounded by the candidate
	// count) and compare their (fileID,line) keys against the BUFFER_ACCESS
	// location-key set — the event store does not deduplicate locations, so a
	// candidate and an event at the same line have DIFFERENT location ids and an
	// id-only comparison would suppress nothing. The key set carries no event
	// rows, so the plan-stage memory peak stays bounded (the OOM fix).
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

	locsByID, err := f.store.ListLocationsByIDs(ctx, locIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("array oob precedence filter: list locations: %w", err)
	}
	covered, err := f.store.ListEventLocationKeysByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		return nil, nil, fmt.Errorf("array oob precedence filter: %w", err)
	}

	kept, dropped := partition(candidates,
		func(c Candidate) bool {
			if !c.NonNullable || c.LocationID <= 0 {
				return true
			}
			loc := locsByID[c.LocationID]
			if loc == nil {
				return true
			}
			return !covered[fmt.Sprintf("%d:%d", loc.FileID, loc.Line)]
		},
		func(c Candidate) string {
			return "array out-of-bounds BUFFER_ACCESS already covers this location"
		},
		f.Name())
	return kept, dropped, nil
}
