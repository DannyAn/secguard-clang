package planner

import (
	"context"
	"encoding/json"

	"github.com/kongan/secguard-lite/internal/db"
)

type GuardFilter struct {
	store db.Store
}

func NewGuardFilter(store db.Store) *GuardFilter {
	return &GuardFilter{store: store}
}

func (f *GuardFilter) Name() string { return "guard" }

func (f *GuardFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	guardEvents, err := f.store.ListEventsByType(ctx, "NULL_GUARD")
	if err != nil {
		return nil, err
	}

	type guardInfo struct {
		variable   string
		scopeStart int
		scopeEnd   int
	}
	funcGuards := make(map[int64][]guardInfo)
	for _, e := range guardEvents {
		var props struct {
			Variable   string `json:"variable"`
			ScopeStart int    `json:"scope_start"`
			ScopeEnd   int    `json:"scope_end"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		funcGuards[e.EntityID] = append(funcGuards[e.EntityID], guardInfo{
			variable:   props.Variable,
			scopeStart: props.ScopeStart,
			scopeEnd:   props.ScopeEnd,
		})
	}

	var result []Candidate
	for _, c := range candidates {
		guarded := false
		for _, g := range funcGuards[c.FunctionID] {
			if g.variable == c.VariableName && c.Line >= g.scopeStart && c.Line <= g.scopeEnd {
				guarded = true
				break
			}
		}
		if !guarded {
			c.IsGuarded = false
			result = append(result, c)
		}
	}
	return result, nil
}
