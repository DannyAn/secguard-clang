package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// querier implements graph.Querier by reusing the pipeline's existing
// null-flow / range-flow engines. It is constructed once per scan (by the
// Planner) and shared across every consumer that needs a semantic answer,
// replacing the per-filter ad-hoc flow rebuilds the architecture review
// identified as the 8-12x duplicate work.
type querier struct {
	store    db.Store
	parser   *parser.Parser
	cfgCache *graph.CFGCache
}

// NewQuerier builds the per-scan Querier. cfgCache is shared with the
// Planner's CFG cache so flow engines hit the same per-function CFG builds.
func NewQuerier(store db.Store, p *parser.Parser, cfgCache *graph.CFGCache) graph.Querier {
	return &querier{store: store, parser: p, cfgCache: cfgCache}
}

// nullFlowFor builds fn's null-source reaching-sources flow via the shared
// engine. The sources come from the scan's NULL_VALUE events (the same
// source pool the NullableSourceFilter consumes), so the answer matches the
// pipeline's null-deref judgment, not a re-derivation. Returns nil when the
// body cannot be located (mock store, missing file, non-compound body) — the
// caller must then fall back to TriUnknown rather than guessing.
func (q *querier) nullFlowFor(ctx context.Context, fn *db.Function) *flowResult {
	if q.parser == nil || q.store == nil || fn == nil {
		return nil
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return nil
	}
	body, root := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return nil
	}
	models, err := buildNullModel(ctx, q.store)
	if err != nil {
		return nil
	}
	sources := nullSourcesFor(models, fn.ID)
	a := newFlowAnalyzer(q.store, q.parser, q.cfgCache)
	return a.analyzeFunction(ctx, fn, body, root, sources)
}

// MayBeNullAt reports whether variable v may be null at line inside fn: a
// nullable source reaches the line on some path. TriYes = a source provably
// reaches; TriUnknown = we cannot prove reach (either no source or the flow
// could not be built) — the caller must NOT treat TriUnknown as "provably
// non-null", only as "no evidence of nullability".
func (q *querier) MayBeNullAt(ctx context.Context, fn *db.Function, v string, line int) graph.Tri {
	flow := q.nullFlowFor(ctx, fn)
	if flow == nil {
		return graph.TriUnknown
	}
	if flow.reaching(v, line) {
		return graph.TriYes
	}
	return graph.TriUnknown
}

// MustNonNullAt reports whether variable v is definitely non-null at line
// inside fn. The conservative truth table:
//   - reachingDefinite(v, line) = true → v is PROVEN null → TriNo (must-non-null
//     is provably false)
//   - otherwise → TriUnknown (we have no must-non-null lattice yet; claiming
//     TriYes without one would let a caller upgrade a candidate on an unsound
//     proof)
//
// A future Phase adds the must-non-null lattice (a guard-dominated reaching
// analysis); until then this seam stays conservative.
func (q *querier) MustNonNullAt(ctx context.Context, fn *db.Function, v string, line int) graph.Tri {
	flow := q.nullFlowFor(ctx, fn)
	if flow == nil {
		return graph.TriUnknown
	}
	if flow.reachingDefinite(v, line) {
		return graph.TriNo
	}
	return graph.TriUnknown
}

// IntervalAt reports the integer interval of variable v at line inside fn,
// using the range-flow engine. The bool is false when the engine has no
// tighter-than-top fact.
func (q *querier) IntervalAt(ctx context.Context, fn *db.Function, v string, line int) (graph.Interval, bool) {
	if q.parser == nil || fn == nil {
		return graph.Interval{Top: true}, false
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return graph.Interval{Top: true}, false
	}
	body, _ := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return graph.Interval{Top: true}, false
	}
	flow := analyzeRangesWithCalls(q.cfgCache, fn, body, nil)
	if flow == nil {
		return graph.Interval{Top: true}, false
	}
	iv := flow.at(v, line)
	if iv.isTop() {
		return graph.Interval{Top: true}, false
	}
	return graph.Interval{Lo: iv.lo, Hi: iv.hi}, true
}

// TypeOf resolves the C type of variable v inside fn from its declaration.
// The skeleton handles plain declarator shapes (`int x`, `unsigned long n`,
// `size_t s`, `double d`, `T *p`): it walks fn's body for the declaration
// of v, reads the type spelling, and resolves it via graph.TypeByName.
// Typedefs, struct names, and expression shapes return ok=false — callers
// must treat that as "type unknown" and keep the candidate at its seeded
// suspicion tier rather than assuming a default.
func (q *querier) TypeOf(ctx context.Context, fn *db.Function, v string) (graph.Type, bool) {
	if q.parser == nil || fn == nil || v == "" {
		return graph.Type{}, false
	}
	cache := newFileParseCache(q.parser)
	file, err := q.store.GetFileByID(ctx, fn.FileID)
	if err != nil || file == nil {
		return graph.Type{}, false
	}
	body, _ := cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		return graph.Type{}, false
	}
	// Scan declarations in fn's body for v.
	for _, decl := range body.FindAll("declaration") {
		typ := decl.ChildByFieldName("type")
		if typ == nil {
			continue
		}
		for _, d := range decl.FindAll("init_declarator") {
			if d.ChildByFieldName("declarator") == nil {
				continue
			}
			name := d.ChildByFieldName("declarator").Text()
			if stripDeclaratorName(name) != v {
				continue
			}
			if t, ok := graph.TypeByName(typ.Text()); ok {
				return t, true
			}
			return graph.Type{}, false
		}
		for _, d := range decl.FindAll("declarator") {
			if stripDeclaratorName(d.Text()) != v {
				continue
			}
			if t, ok := graph.TypeByName(typ.Text()); ok {
				return t, true
			}
			return graph.Type{}, false
		}
	}
	// Parameter fallback: walk up from body to the function_definition's
	// declarator and scan its parameter_list for v.
	if t, ok := typeOfParameter(body, v); ok {
		return t, true
	}
	return graph.Type{}, false
}

// typeOfParameter resolves v's type from fn's parameter_list when v is a
// parameter. body is fn's compound_statement; its parent is the
// function_definition, whose declarator carries the parameter_list. Returns
// ok=false when v is not a parameter or its type is not a recognized name.
func typeOfParameter(body parser.Node, v string) (graph.Type, bool) {
	// body.Parent is the function_definition.
	fd := body.Parent()
	if fd == nil || fd.Kind() != "function_definition" {
		return graph.Type{}, false
	}
	decl := fd.ChildByFieldName("declarator")
	if decl == nil {
		return graph.Type{}, false
	}
	// declarator may nest (pointer_declarator / function_declarator); find
	// the parameter_list anywhere under it.
	var params parser.Node
	var findParams func(n parser.Node)
	findParams = func(n parser.Node) {
		if params.Kind() != "" {
			return
		}
		if n.Kind() == "parameter_list" {
			params = n
			return
		}
		for _, c := range n.Children() {
			findParams(c)
		}
	}
	findParams(*decl)
	if params.Kind() == "" {
		return graph.Type{}, false
	}
	for _, pdecl := range params.FindAll("parameter_declaration") {
		typ := pdecl.ChildByFieldName("type")
		pdeclDeclarator := pdecl.ChildByFieldName("declarator")
		if typ == nil || pdeclDeclarator == nil {
			continue
		}
		if stripDeclaratorName(pdeclDeclarator.Text()) != v {
			continue
		}
		if t, ok := graph.TypeByName(typ.Text()); ok {
			return t, true
		}
		return graph.Type{}, false
	}
	return graph.Type{}, false
}

// stripDeclaratorName peels pointer stars and array brackets off a
// declarator text so `*p` matches `p`, `arr[8]` matches `arr`.
func stripDeclaratorName(s string) string {
	for len(s) > 0 && (s[0] == '*' || s[0] == ' ') {
		s = s[1:]
	}
	for i, c := range s {
		if c == '[' || c == '(' {
			return s[:i]
		}
	}
	return s
}
