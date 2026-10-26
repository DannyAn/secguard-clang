package planner

import (
	"context"
	"encoding/json"
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
	// nodeName maps a graph node ID to the function name it represents (the
	// inverse of funcNodeMap, for rendering a concrete call chain).
	nodeName map[int64]string
	// nodeFile maps a graph node ID to the source file of the function it
	// represents, so a hop renders "f → g (pool.c:42)".
	nodeFile map[int64]string
	// parent records the BFS predecessor node of each reachable node, so the
	// entry -> ... -> sink path can be reconstructed (first-discovered = one
	// shortest edge path). Nil for entry nodes.
	parent map[int64]int64
	// callLine maps a (caller node, callee node) pair to the call site line in
	// the caller (from the CALL edge's call_line property), for the per-hop
	// annotation "called at <file>:<line>". 0 = unknown (e.g. an external CALL
	// edge, which carries the callee name but no site).
	callLine map[[2]int64]int
}

// CallChainHop is one hop of the concrete cross-function call chain.
type CallChainHop struct {
	Caller string `json:"caller"`
	Callee string `json:"callee"`
	Line   int    `json:"line,omitempty"`
	// File is the CALLER's source file (the call site lives there), so a hop
	// renders as "f → g (pool.c:42)" and the reviewer can open the exact call.
	File string `json:"file,omitempty"`
}

// callChain returns the concrete entry -> ... -> funcID call path (caller name
// -> callee name with the call site line), or nil when the function has no
// function node or is an entry itself. The first hop's caller is the entry
// (main / an exported function / an address-taken function), whose "call site"
// has no line.
func (r *callReachResult) callChain(funcID int64) []CallChainHop {
	if r == nil || r.parent == nil {
		return nil
	}
	nodeID, ok := r.funcNodeMap[funcID]
	if !ok {
		return nil
	}
	var rev []CallChainHop
	for {
		prev, hasParent := r.parent[nodeID]
		if !hasParent || prev == nodeID {
			break
		}
		rev = append(rev, CallChainHop{
			Caller: r.nodeName[prev],
			Callee: r.nodeName[nodeID],
			Line:   r.callLine[[2]int64{prev, nodeID}],
			File:   r.nodeFile[prev],
		})
		nodeID = prev
	}
	if len(rev) == 0 {
		return nil
	}
	out := make([]CallChainHop, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		out = append(out, rev[i])
	}
	return out
}

// callReachCache memoizes callReachResult across the Planner's Plan() calls.
// All 15 vulnerability types run the call-reach filter over the same graph,
// so recomputing it per type was the dominant scan wall-time cost (a recursive
// CTE over ~79k CALL edges repeated 15x). Only a SUCCESS is cached: a transient
// failure (e.g. SQLITE_BUSY) must not be frozen in place — the next Plan()
// retries the computation instead of inheriting a stale error that would fail
// every remaining type.
type callReachCache struct {
	mu   sync.Mutex
	done bool
	res  *callReachResult
	err  error
}

func (c *callReachCache) get(ctx context.Context, store db.Store) (*callReachResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return c.res, c.err
	}
	c.res, c.err = computeCallReach(ctx, store)
	if c.err == nil {
		c.done = true
	}
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

	// Address-referenced functions (function-pointer tables, pthread_create
	// thread fn, callback registration) are invoked indirectly, so the direct
	// CALL graph has no edge into them. The graph layer marks each with a
	// self-loop ADDR_TAKEN edge; treat its source as an entry point so a static
	// function wired up through a pointer table is not dropped as "unreachable"
	// (a systematic false negative across every vuln type).
	addrEdges, err := store.ListGraphEdgesByType(ctx, "ADDR_TAKEN")
	if err != nil {
		return nil, fmt.Errorf("filter call reach: list addr-taken edges: %w", err)
	}
	seen := make(map[int64]bool, len(entryNodeIDs))
	for _, n := range entryNodeIDs {
		seen[n] = true
	}
	addrNodeIDs := make([]int64, 0, len(addrEdges))
	for _, e := range addrEdges {
		addrNodeIDs = append(addrNodeIDs, e.SrcID)
		if !seen[e.SrcID] {
			seen[e.SrcID] = true
			entryNodeIDs = append(entryNodeIDs, e.SrcID)
		}
	}

	// nodeName: node ID -> function name, so a reconstructed chain reads as
	// "main -> init -> pool_cmd_stat" rather than a list of opaque node IDs.
	nodeName := make(map[int64]string, len(funcs))
	nodeFile := make(map[int64]string, len(funcs))
	fileByID := make(map[int64]string)
	if files, ferr := store.ListFiles(ctx); ferr == nil {
		for _, fl := range files {
			fileByID[fl.ID] = fl.Path
		}
	}
	for _, fn := range funcs {
		if nodeID, ok := funcNodeMap[fn.ID]; ok {
			nodeName[nodeID] = fn.Name
			nodeFile[nodeID] = fileByID[fn.FileID]
		}
	}

	// Build the CALL adjacency (and its reverse) in memory, recording the call
	// site line of each (caller, callee) edge so the chain can be annotated hop
	// by hop.
	edges, err := store.ListGraphEdgesByType(ctx, "CALL")
	if err != nil {
		return nil, fmt.Errorf("filter call reach: list call edges: %w", err)
	}
	adj := make(map[int64][]int64, len(edges))
	rev := make(map[int64][]int64, len(edges))
	callLine := make(map[[2]int64]int, len(edges))
	for _, e := range edges {
		adj[e.SrcID] = append(adj[e.SrcID], e.DstID)
		rev[e.DstID] = append(rev[e.DstID], e.SrcID)
		if line := edgeCallLine(e.Properties); line > 0 {
			callLine[[2]int64{e.SrcID, e.DstID}] = line
		}
	}

	// Reachability keeps the ORIGINAL semantics: BFS from every entry (main,
	// non-static, address-taken), so a static function reached only through a
	// non-static function is still reachable.
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

	// The concrete CHAIN starts only from the true entries (main + address-taken
	// functions, invoked WITHOUT an in-tree caller). A non-static function is
	// also externally callable, but when an in-tree caller exists the concrete
	// chain through it is the diagnosis the reviewer needs.
	trueEntries := make([]int64, 0, len(entryNodeIDs))
	entryIsTrue := make(map[int64]bool, len(entryNodeIDs))
	for _, fn := range funcs {
		if nodeID, ok := funcNodeMap[fn.ID]; ok && fn.Name == "main" {
			entryIsTrue[nodeID] = true
			trueEntries = append(trueEntries, nodeID)
		}
	}
	trueEntries = append(trueEntries, addrNodeIDs...)
	parent := make(map[int64]int64, len(funcNodeMap))
	queue = make([]int64, 0, len(trueEntries))
	for _, n := range trueEntries {
		if _, seen := parent[n]; !seen {
			parent[n] = n // sentinel: a true entry has no parent, but must be discoverable
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, dst := range adj[n] {
			if _, seen := parent[dst]; !seen {
				parent[dst] = n
				queue = append(queue, dst)
			}
		}
	}

	// Adopt a concrete caller where one exists: a non-static function that has
	// no true-entry chain (its parent is the self-sentinel or absent) but IS
	// called in-tree by a reachable function gets linked to that caller, so
	// `apply_setting` called only by `load_config` still reports
	// `main → load_config → apply_setting` instead of "entry".
	for node := range reachable {
		p, hasParent := parent[node]
		if hasParent && p != node {
			continue // already on a concrete chain
		}
		for _, caller := range rev[node] {
			if caller == node {
				continue
			}
			if cp, ok := parent[caller]; ok && cp != caller || entryIsTrue[caller] {
				parent[node] = caller
				break
			}
		}
	}

	return &callReachResult{
		funcNodeMap:  funcNodeMap,
		entryNodeIDs: entryNodeIDs,
		reachable:    reachable,
		nodeName:     nodeName,
		nodeFile:     nodeFile,
		parent:       parent,
		callLine:     callLine,
	}, nil
}

// edgeCallLine extracts the CALL edge's call-site line from its JSON properties
// (`{"call_line": N}`); 0 when absent (an external CALL edge carries only the
// callee name).
func edgeCallLine(props string) int {
	var v struct {
		CallLine int `json:"call_line"`
	}
	if err := json.Unmarshal([]byte(props), &v); err != nil {
		return 0
	}
	return v.CallLine
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
		// FunctionID == 0 means the event is not attached to any function — a
		// file-scope declaration (a global secret initializer) that runs at
		// load time regardless of the call graph. Dropping it as "unreachable"
		// would be a false negative; keep it and mark it reachable.
		if c.FunctionID == 0 {
			c.IsReachable = true
			kept = append(kept, c)
			continue
		}
		nodeID, ok := res.funcNodeMap[c.FunctionID]
		if !ok {
			// No function graph node for this function (the graph build failed,
			// skipped this function, or a stale incremental index predates it).
			// Dropping the candidate as "not reachable" would be a silent false
			// negative; fail OPEN and let the AI review it.
			c.IsReachable = true
			kept = append(kept, c)
			continue
		}
		if res.reachable[nodeID] {
			c.IsReachable = true
			c.CallChain = res.callChain(c.FunctionID)
			kept = append(kept, c)
			continue
		}
		dropped = dismiss(dropped, c, f.Name(),
			fmt.Sprintf("function %s is not reachable from an entry point", c.FunctionName))
	}
	return kept, dropped, nil
}
