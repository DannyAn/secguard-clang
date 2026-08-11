package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kongan/secguard-lite/internal/db"
)

type ArrayOOBPrecedenceFilter struct {
	store db.Store
}

func NewArrayOOBPrecedenceFilter(store db.Store) *ArrayOOBPrecedenceFilter {
	return &ArrayOOBPrecedenceFilter{store: store}
}

func (f *ArrayOOBPrecedenceFilter) Name() string { return "array_oob_precedence" }

func (f *ArrayOOBPrecedenceFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	bofEvents, err := f.store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		return nil, fmt.Errorf("array oob precedence filter: %w", err)
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

	var result []Candidate
	for _, c := range candidates {
		if c.NonNullable && c.LocationID > 0 {
			loc, _ := f.store.GetLocationByID(ctx, c.LocationID)
			if loc != nil {
				key := fmt.Sprintf("%d:%d", loc.FileID, loc.Line)
				if bofLocations[key] {
					continue
				}
			}
		}
		result = append(result, c)
	}
	return result, nil
}

var _ = json.Marshal
