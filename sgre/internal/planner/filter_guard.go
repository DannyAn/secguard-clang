package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

type GuardFilter struct {
	store db.Store
}

func NewGuardFilter(store db.Store) *GuardFilter {
	return &GuardFilter{store: store}
}

func (f *GuardFilter) Name() string { return "guard" }

func (f *GuardFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	guardEvents, err := f.store.ListEventsByType(ctx, "NULL_GUARD")
	if err != nil {
		return nil, nil, fmt.Errorf("guard filter: %w", err)
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

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		guarded := false
		for _, g := range funcGuards[c.FunctionID] {
			if g.variable == c.VariableName && c.Line >= g.scopeStart && c.Line <= g.scopeEnd {
				guarded = true
				break
			}
		}
		if guarded {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("dereference of %s at line %d is inside a null-guard scope", c.VariableName, c.Line))
			continue
		}
		c.IsGuarded = false
		kept = append(kept, c)
	}
	return kept, dropped, nil
}
