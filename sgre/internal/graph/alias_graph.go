package graph

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// AliasKey identifies a tracked storage location across the program: a local
// variable of a specific function, an extern global (one object program-wide),
// or a static global (one object per file).
type AliasKey struct {
	// FunctionID > 0 identifies a function-local variable; 0 identifies a
	// global / file-scope name.
	FunctionID int64
	// FileID distinguishes a static global (FileID = its file, internal
	// linkage, one object per file) from an extern global (FileID = 0,
	// external linkage, one object program-wide). Function-local keys always
	// have FileID = 0 (the FunctionID already disambiguates them).
	FileID int64
	Name   string
}

// AliasGraph maps an AliasKey to the set of AliasKeys that may refer to the
// same underlying object. It is the data structure UAF / double-free /
// memory-leak / resource-leak consume so `q = p; free(q)` is recognized as
// releasing p, `free((void*)p)` as freeing p, and a global `g = (T*)p` as
// aliasing p across function boundaries.
// AliasEdgeKind tags the provenance of an alias edge: which C shape created
// it. Consumers can distinguish "one object, two owners" (return-alias) from
// "same name, different object on every call" (parameter-alias) with
// AliasesOfKind.
type AliasEdgeKind int

const (
	// AliasEdgeLocal is a function-local alias (declaration initializer /
	// plain assignment / cast / field / element-address).
	AliasEdgeLocal AliasEdgeKind = iota
	// AliasEdgeReturn is a cross-function return alias: `q = foo()` in the
	// caller + `return p;` in foo links q to p (foo's local).
	AliasEdgeReturn
	// AliasEdgeReturnDangling is a cross-function return alias where foo
	// UNCONDITIONALLY frees its return source (`free(p); return p;`): every
	// caller that frees q = foo() is a genuine cross-function double-free.
	// It is the sound gate for the cross-function double-free aggregation —
	// a live return (`return p` on the success path only) stays AliasEdgeReturn
	// and does NOT participate.
	AliasEdgeReturnDangling
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
// traversal only follows edges whose provenance matches. It is the seam a
// provenance-aware consumer (e.g. a future cross-function double-free) uses to
// separate return-alias (one object crossing a call) from parameter-alias
// (same name, potentially a different object on every call). The graph is
// flow- and call-site-insensitive, so kind-filtering alone is not sound for
// that consumer — it also needs one-object-per-call accounting.
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
		if aliasKeyLess(k2, best) {
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
// AliasKey with the smallest (FunctionID, FileID, Name) in lexicographic
// order. Consumers that aggregate events across functions use this to key the
// group so `free(p)` in A and `free(q)` in B (q a cross-function alias of p)
// collapse into one defect.
func (g *AliasGraph) CanonicalKey(k AliasKey) AliasKey {
	set := g.AliasesOf(k)
	best := set[0]
	for _, k2 := range set[1:] {
		if aliasKeyLess(k2, best) {
			best = k2
		}
	}
	return best
}

// aliasKeyLess orders keys by (FunctionID, FileID, Name) so a static global in
// file A and one in file B (same FunctionID=0, same Name, different FileID) are
// distinct representatives.
func aliasKeyLess(a, b AliasKey) bool {
	if a.FunctionID != b.FunctionID {
		return a.FunctionID < b.FunctionID
	}
	if a.FileID != b.FileID {
		return a.FileID < b.FileID
	}
	return a.Name < b.Name
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
