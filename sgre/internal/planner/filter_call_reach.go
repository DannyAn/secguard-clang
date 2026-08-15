package planner

import (
	"context"
	"fmt"
	"sync"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// callReachResult is the precomputed call-graph reachability used by the
// call-reach filter: the function-ID -> graph-node-ID map, the entry node IDs,
// and the set of node IDs reachable from those entries over CALL edges.
// It depends only on the graph layer (functions + CALL edges), so it is
// identical for every vulnerability type and is computed once per Planner.
type callReachResult struct {
	funcNodeMap  map[int64]int64 // function ID -> graph node ID
	entryNodeIDs []int64
	reachable    map[int64]bool
}

// callReachCache memoizes callReachResult across the Planner's Plan() calls.
// All 15 vulnerability types run the call-reach filter over the same graph,
// so recomputing it per type was the dominant scan wall-time cost (a recursive
// CTE over ~79k CALL edges repeated 15x). sync.Once makes the cache safe even
// if Plan is ever driven concurrently.
type callReachCache struct {
	once sync.Once
	res  *callReachResult
	err  error
}

func (c *callReachCache) get(ctx context.Context, store db.Store) (*callReachResult, error) {
	c.once.Do(func() {
		c.res, c.err = computeCallReach(ctx, store)
	})
	return c.res, c.err
}

// computeCallReach loads the function nodes and CALL edges once each and runs
// an in-memory BFS from the entry nodes. This replaces the previous per-call
// approach: ListGraphNodesByEntity once per function (an N+1 query storm) plus
// a recursive CTE with implicit DISTINCT (UNION) over the whole call graph.
// The in-memory BFS is O(V+E) and avoids both.
func computeCallReach(ctx context.Context, store db.Store) (*callReachResult, error) {
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("filter call reach: list functions: %w", err)
	}

	// One query for every function node, then build the function->node map.
	nodes, err := store.ListGraphNodesByEntityType(ctx, "function")
	if err != nil {
		return nil, fmt.Errorf("filter call reach: list function nodes: %w", err)
	}
	funcNodeMap := make(map[int64]int64, len(nodes))
	for _, n := range nodes {
		if _, ok := funcNodeMap[n.EntityID]; !ok {
			funcNodeMap[n.EntityID] = n.ID
		}
	}

	// Entry points: main() and every non-static (externally callable) function.
	entryNodeIDs := make([]int64, 0, len(funcs))
	for _, fn := range funcs {
		if nodeID, ok := funcNodeMap[fn.ID]; ok {
			if fn.Name == "main" || !fn.IsStatic {
				entryNodeIDs = append(entryNodeIDs, nodeID)
			}
		}
	}

	// Build the CALL adjacency list in memory and BFS from the entries.
	edges, err := store.ListGraphEdgesByType(ctx, "CALL")
	if err != nil {
		return nil, fmt.Errorf("filter call reach: list call edges: %w", err)
	}
	adj := make(map[int64][]int64, len(edges))
	for _, e := range edges {
		adj[e.SrcID] = append(adj[e.SrcID], e.DstID)
	}

	reachable := make(map[int64]bool)
	queue := make([]int64, 0, len(entryNodeIDs))
	for _, n := range entryNodeIDs {
		if !reachable[n] {
			reachable[n] = true
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, dst := range adj[n] {
			if !reachable[dst] {
				reachable[dst] = true
				queue = append(queue, dst)
			}
		}
	}

	return &callReachResult{
		funcNodeMap:  funcNodeMap,
		entryNodeIDs: entryNodeIDs,
		reachable:    reachable,
	}, nil
}

type CallReachFilter struct {
	store db.Store
	cache *callReachCache
}

func NewCallReachFilter(store db.Store, cache *callReachCache) *CallReachFilter {
	return &CallReachFilter{store: store, cache: cache}
}

func (f *CallReachFilter) Name() string { return "call_reach" }

func (f *CallReachFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if len(candidates) == 0 {
		return candidates, nil, nil
	}

	res, err := f.cache.get(ctx, f.store)
	if err != nil {
		return nil, nil, err
	}

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		nodeID, ok := res.funcNodeMap[c.FunctionID]
		if ok && res.reachable[nodeID] {
			c.IsReachable = true
			kept = append(kept, c)
			continue
		}
		dropped = dismiss(dropped, c, f.Name(),
			fmt.Sprintf("function %s is not reachable from an entry point", c.FunctionName))
	}
	return kept, dropped, nil
}
