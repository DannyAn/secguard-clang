package planner

import (
	"context"
	"fmt"

	"github.com/kongan/secguard-lite/internal/db"
)

type CallReachFilter struct {
	store db.Store
}

func NewCallReachFilter(store db.Store) *CallReachFilter {
	return &CallReachFilter{store: store}
}

func (f *CallReachFilter) Name() string { return "call_reach" }

func (f *CallReachFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	if len(candidates) == 0 {
		return candidates, nil
	}

	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("filter call reach: list functions: %w", err)
	}

	funcNodeMap := make(map[int64]int64)
	for _, fn := range funcs {
		nodes, _ := f.store.ListGraphNodesByEntity(ctx, "function", fn.ID)
		if len(nodes) > 0 {
			funcNodeMap[fn.ID] = nodes[0].ID
		}
	}

	reachableSet := make(map[int64]bool)
	for _, fn := range funcs {
		if fn.Name == "main" || fn.IsStatic == false {
			nodeID, ok := funcNodeMap[fn.ID]
			if !ok {
				continue
			}
			reachable, _ := f.store.ReachableFromEntry(ctx, nodeID, "CALL")
			for _, r := range reachable {
				reachableSet[r] = true
			}
		}
	}

	var result []Candidate
	for _, c := range candidates {
		nodeID, ok := funcNodeMap[c.FunctionID]
		if ok && reachableSet[nodeID] {
			c.IsReachable = true
			result = append(result, c)
		}
	}
	return result, nil
}
