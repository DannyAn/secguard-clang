package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// NullableSourceFilter drops null-deref candidates whose variable has no null
// source that can actually reach the dereference. It is the convergence stage
// where the semantic graph is consumed: when a parser is available it runs a
// flow-sensitive "may be null" analysis over the statement CFG and DATA_FLOW
// edges (see null_flow.go); otherwise it falls back to the earlier line-order
// heuristic so offline/mock callers keep working.
type NullableSourceFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewNullableSourceFilter(store db.Store) *NullableSourceFilter {
	return &NullableSourceFilter{store: store}
}

// WithParser enables the flow-sensitive graph analysis. It is optional; without
// a parser the filter degrades to the line-order fallback.
func (f *NullableSourceFilter) WithParser(p *parser.Parser, l *log.Logger) *NullableSourceFilter {
	f.parser = p
	f.logger = l
	return f
}

func (f *NullableSourceFilter) Name() string { return "nullable_source" }

func (f *NullableSourceFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	models, err := buildNullModel(ctx, f.store)
	if err != nil {
		return nil, nil, fmt.Errorf("filter nullable source: %w", err)
	}

	// Bucket candidates by function so each function is parsed and analysed once.
	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		if c.NonNullable {
			// Handled identically to the old filter; kept here so the drop
			// reason stays attributable to this stage.
			continue
		}
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}

	flowResults := f.buildFlowResults(ctx, byFunc, models)

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		if c.NonNullable {
			dropped = dismiss(dropped, c, f.Name(), "variable is non-nullable")
			continue
		}

		fm := flowResults[c.FunctionID]
		if fm != nil {
			if fm.reaching(c.VariableName, c.Line) {
				c.HasNullableSource = true
				c.HasDefiniteNull = fm.reachingDefinite(c.VariableName, c.Line)
				c.SourceLine = fm.sourceLine(c.VariableName, c.Line)
				// Layering: reflect the must/may tier in the suspicion label so
				// the AI budgets effort by certainty. A DEFINITE null source
				// (p = NULL) reaching on every path is a certain null-deref →
				// confirmed; a possible-null source (malloc/function return) is
				// only maybe-null → suspected, so the AI reasons about it instead
				// of rubber-stamping a "confirmed" prior.
				if !c.HasDefiniteNull {
					c.SuspicionLevel = "suspected"
				}
				kept = append(kept, c)
			} else {
				dropped = dismiss(dropped, c, f.Name(),
					fmt.Sprintf("no null source reaches variable %s at line %d (flow-sensitive CFG/DFG analysis)", c.VariableName, c.Line))
			}
			continue
		}

		// Fallback: line-order heuristic (no parser, unreadable file, or
		// degenerate CFG). It cannot prove definite null, so a kept candidate is
		// labelled suspected (conservative) rather than confirmed.
		if models[c.FunctionID].hasSource(c.VariableName, c.Line) {
			c.HasNullableSource = true
			c.SuspicionLevel = "suspected"
			kept = append(kept, c)
		} else {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("no nullable source for variable %s before line %d", c.VariableName, c.Line))
		}
	}
	return kept, dropped, nil
}

// buildFlowResults runs the flow-sensitive analysis for each function that has
// candidates, returning nil for functions it cannot analyse (so the caller
// falls back to the line-order heuristic).
func (f *NullableSourceFilter) buildFlowResults(ctx context.Context, byFunc map[int64][]Candidate, models map[int64]*nullModel) map[int64]*flowResult {
	if f.parser == nil {
		return nil
	}

	funcIDs := make([]int64, 0, len(byFunc))
	for fid := range byFunc {
		funcIDs = append(funcIDs, fid)
	}

	analyzer := newFlowAnalyzer(f.store, f.parser)
	analyzer.dfgCopies = analyzer.loadDFGCopies(ctx, funcIDs)

	// Inter-procedural return-nullability: which functions can return NULL.
	// This wires the RETURN edges + function_summary into the flow engine, so
	// `p = f()` becomes a possible-null source when f can return NULL (previously
	// the call was treated as a variable copy and silently cleared p's null
	// state, dropping the candidate). Fail-open on error: keep candidates.
	retNullable, err := f.computeRetNullable(ctx, models)
	if err != nil {
		retNullable = map[string]bool{}
	}

	cache := newFileParseCache(f.parser)
	results := make(map[int64]*flowResult, len(byFunc))
	for fid := range byFunc {
		fn, err := f.store.GetFunctionByID(ctx, fid)
		if err != nil || fn == nil {
			continue
		}
		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		sources := nullSourcesFor(models, fid)
		sources = append(sources, callResultNullSources(body, retNullable)...)
		results[fid] = analyzer.analyzeFunction(ctx, fn, body, root, sources)
	}
	return results
}

// computeRetNullable returns the set of function NAMES that can return a
// possibly-null pointer, as a monotone fixpoint over the call graph. It seeds
// from function_summary.return_nullable (literal `return NULL`), then adds any
// function whose body returns an allocator, a pointer parameter, a variable with
// a reaching may-null source, or a call to another nullable-returning function.
// This is the null-deref analogue of the taint filter's computeRetTainted and is
// what makes the persisted RETURN edges useful to the convergence stage.
func (f *NullableSourceFilter) computeRetNullable(ctx context.Context, models map[int64]*nullModel) (map[string]bool, error) {
	retNullable := make(map[string]bool)
	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("ret nullable summary: list functions: %w", err)
	}

	type funcInfo struct {
		fn     *db.Function
		body   parser.Node
		root   parser.Node
		params map[string]int
		srcs   []nullSource
	}
	infos := make([]funcInfo, 0, len(funcs))
	cache := newFileParseCache(f.parser)
	for _, fn := range funcs {
		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		var srcs []nullSource
		if models != nil && models[fn.ID] != nil {
			srcs = models[fn.ID].sources
		}
		infos = append(infos, funcInfo{fn: fn, body: body, root: root, params: paramsOf(fn, root), srcs: srcs})

		// Seed from the detector's function_summary (literal `return NULL`/`0`).
		if sum, err := f.store.GetSummaryByFunction(ctx, fn.ID); err == nil && sum != nil && sum.ReturnNullable {
			retNullable[fn.Name] = true
		}
	}

	allIDs := make([]int64, 0, len(infos))
	for i := range infos {
		allIDs = append(allIDs, infos[i].fn.ID)
	}
	analyzer := newFlowAnalyzer(f.store, f.parser)
	analyzer.dfgCopies = analyzer.loadDFGCopies(ctx, allIDs)

	for {
		changed := false
		for i := range infos {
			info := &infos[i]
			if retNullable[info.fn.Name] {
				continue
			}
			srcs := append([]nullSource(nil), info.srcs...)
			srcs = append(srcs, callResultNullSources(info.body, retNullable)...)
			flow := analyzer.analyzeFlow(ctx, info.fn, info.body, info.root, nullGenByLine(srcs), nil, true, false)
			if returnsNullable(info.body, flow, info.params, retNullable) {
				retNullable[info.fn.Name] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return retNullable, nil
}

// nullGenByLine folds a slice of null sources into the per-line gen map the
// may-null flow engine consumes.
func nullGenByLine(srcs []nullSource) map[int][]string {
	gen := make(map[int][]string)
	for _, s := range srcs {
		gen[s.line] = append(gen[s.line], s.variable)
	}
	return gen
}

func nullSourcesFor(m map[int64]*nullModel, fid int64) []nullSource {
	if m == nil || m[fid] == nil {
		return nil
	}
	return m[fid].sources
}
