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

	bofLocations := make(map[string]bool)
	for _, e := range bofEvents {
		if e.LocationID > 0 {
			loc, _ := f.store.GetLocationByID(ctx, e.LocationID)
			if loc != nil {
				key := fmt.Sprintf("%d:%d", loc.FileID, loc.Line)
				bofLocations[key] = true
			}
		}
	}

	kept, dropped := partition(candidates,
		func(c Candidate) bool {
			if c.NonNullable && c.LocationID > 0 {
				loc, _ := f.store.GetLocationByID(ctx, c.LocationID)
				if loc != nil {
					key := fmt.Sprintf("%d:%d", loc.FileID, loc.Line)
					if bofLocations[key] {
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
