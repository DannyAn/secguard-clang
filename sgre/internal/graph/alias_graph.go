package graph

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// AliasKey identifies a tracked storage location across the program: either
// a local variable of a specific function, or a global.
type AliasKey struct {
	// FunctionID > 0 identifies a function-local variable; 0 identifies a
	// global.
	FunctionID int64
	Name       string
}

// AliasGraph maps an AliasKey to the set of AliasKeys that may refer to the
// same underlying object. It is the data structure UAF / double-free /
// memory-leak / resource-leak consume so `q = p; free(q)` is recognized as
// releasing p, `free((void*)p)` as freeing p, and a global `g = (T*)p` as
// aliasing p across function boundaries.
type AliasGraph struct {
	// edges is the adjacency list. Aliasing is symmetric in the current
	// model (q = p makes them aliases of each other); a future phase may
	// need directed "points-to" if flow sensitivity matters.
	edges map[AliasKey][]AliasKey
}

// NewAliasGraph builds an empty graph; the interprocedural builder fills it.
func NewAliasGraph() *AliasGraph {
	return &AliasGraph{edges: make(map[AliasKey][]AliasKey)}
}

// Add records a bidirectional alias between a and b.
func (g *AliasGraph) Add(a, b AliasKey) {
	if a == b {
		return
	}
	g.edges[a] = appendUniqueAlias(g.edges[a], b)
	g.edges[b] = appendUniqueAlias(g.edges[b], a)
}

// AliasesOf returns the transitive closure of aliases of k (including k
// itself), deduplicated.
func (g *AliasGraph) AliasesOf(k AliasKey) []AliasKey {
	if g == nil {
		return []AliasKey{k}
	}
	seen := map[AliasKey]bool{k: true}
	queue := []AliasKey{k}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range g.edges[cur] {
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
	out := make([]AliasKey, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func appendUniqueAlias(xs []AliasKey, k AliasKey) []AliasKey {
	for _, x := range xs {
		if x == k {
			return xs
		}
	}
	return append(xs, k)
}

// AliasQuerier is the interface the detectors consume. It is separate from
// Querier so the two can evolve independently (the null/range flows are
// flow-sensitive; aliasing is currently flow-insensitive).
type AliasQuerier interface {
	// AliasSet returns every name that may alias v inside fn at the given
	// line, including v itself. line is currently unused (flow-insensitive)
	// but reserved for a future path-sensitive version.
	AliasSet(ctx context.Context, fn *db.Function, v string, line int) []string
}
