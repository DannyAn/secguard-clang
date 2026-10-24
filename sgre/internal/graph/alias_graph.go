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
// AliasEdgeKind tags the provenance of an alias edge: which C shape created
// it. The cross-function double-free aggregation consumes it to distinguish
// "one object, two owners" (return-alias) from "same name, different object
// on every call" (parameter-alias).
type AliasEdgeKind int

const (
	// AliasEdgeLocal is a function-local alias (declaration initializer /
	// plain assignment / cast / field / element-address).
	AliasEdgeLocal AliasEdgeKind = iota
	// AliasEdgeReturn is a cross-function return alias: `q = foo()` in the
	// caller + `return p;` in foo links q to p (foo's local).
	AliasEdgeReturn
	// AliasEdgeParam is a cross-function parameter alias: `foo(p)` in the
	// caller + foo's formal `x` links p to x (foo's parameter).
	AliasEdgeParam
	// AliasEdgeGlobal is a global alias: `g = p` where g is not a local of
	// the current function links g (FunctionID=0) to p.
	AliasEdgeGlobal
)

type AliasGraph struct {
	// edges is the adjacency list. Aliasing is symmetric in the current
	// model (q = p makes them aliases of each other); a future phase may
	// need directed "points-to" if flow sensitivity matters.
	edges map[AliasKey][]AliasKey
	// edgeKinds tags each directed edge's provenance. The key is the ordered
	// pair (from, to); both directions of a bidirectional alias carry the
	// same kind.
	edgeKinds map[[2]AliasKey]AliasEdgeKind
}

// NewAliasGraph builds an empty graph; the interprocedural builder fills it.
func NewAliasGraph() *AliasGraph {
	return &AliasGraph{edges: make(map[AliasKey][]AliasKey), edgeKinds: make(map[[2]AliasKey]AliasEdgeKind)}
}

// Add records a bidirectional LOCAL alias between a and b (the legacy
// behavior — callers that know the provenance should use AddWithKind).
func (g *AliasGraph) Add(a, b AliasKey) {
	g.AddWithKind(a, b, AliasEdgeLocal)
}

// AddWithKind records a bidirectional alias between a and b, tagged with the
// edge's provenance kind.
func (g *AliasGraph) AddWithKind(a, b AliasKey, kind AliasEdgeKind) {
	if a == b {
		return
	}
	g.edges[a] = appendUniqueAlias(g.edges[a], b)
	g.edges[b] = appendUniqueAlias(g.edges[b], a)
	g.edgeKinds[[2]AliasKey{a, b}] = kind
	g.edgeKinds[[2]AliasKey{b, a}] = kind
}

// EdgeKind returns the provenance kind of the edge from a to b, or
// AliasEdgeLocal when the edge is untagged (a legacy Add call).
func (g *AliasGraph) EdgeKind(a, b AliasKey) AliasEdgeKind {
	if g == nil {
		return AliasEdgeLocal
	}
	if k, ok := g.edgeKinds[[2]AliasKey{a, b}]; ok {
		return k
	}
	return AliasEdgeLocal
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

// AliasesOfKind is AliasesOf filtered to edges of the given kind: the
// traversal only follows edges whose provenance matches. The cross-function
// double-free aggregation uses it with AliasEdgeReturn so a parameter-alias
// (`foo(p)` + `free(p)` inside foo + `free(p)` in the caller) does NOT
// collapse the two frees into one defect (the caller's p is a different
// object on every call).
func (g *AliasGraph) AliasesOfKind(k AliasKey, kind AliasEdgeKind) []AliasKey {
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
			if g.EdgeKind(cur, next) != kind {
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

// CanonicalKeyOfKind is CanonicalKey restricted to edges of the given kind.
func (g *AliasGraph) CanonicalKeyOfKind(k AliasKey, kind AliasEdgeKind) AliasKey {
	set := g.AliasesOfKind(k, kind)
	best := set[0]
	for _, k2 := range set[1:] {
		if k2.FunctionID < best.FunctionID || (k2.FunctionID == best.FunctionID && k2.Name < best.Name) {
			best = k2
		}
	}
	return best
}

func appendUniqueAlias(xs []AliasKey, k AliasKey) []AliasKey {
	for _, x := range xs {
		if x == k {
			return xs
		}
	}
	return append(xs, k)
}

// CanonicalKey returns the canonical representative of k's alias set: the
// AliasKey with the smallest (FunctionID, Name) in lexicographic order.
// Consumers that aggregate events across functions use this to key the
// group so `free(p)` in A and `free(q)` in B (q a cross-function alias of p)
// collapse into one defect.
func (g *AliasGraph) CanonicalKey(k AliasKey) AliasKey {
	set := g.AliasesOf(k)
	best := set[0]
	for _, k2 := range set[1:] {
		if k2.FunctionID < best.FunctionID || (k2.FunctionID == best.FunctionID && k2.Name < best.Name) {
			best = k2
		}
	}
	return best
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
