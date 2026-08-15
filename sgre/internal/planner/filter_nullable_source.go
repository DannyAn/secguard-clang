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
				kept = append(kept, c)
			} else {
				dropped = dismiss(dropped, c, f.Name(),
					fmt.Sprintf("no null source reaches variable %s at line %d (flow-sensitive CFG/DFG analysis)", c.VariableName, c.Line))
			}
			continue
		}

		// Fallback: line-order heuristic (no parser, unreadable file, or
		// degenerate CFG).
		if models[c.FunctionID].hasSource(c.VariableName, c.Line) {
			c.HasNullableSource = true
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
		results[fid] = analyzer.analyzeFunction(ctx, fn, body, root, nullSourcesFor(models, fid))
	}
	return results
}

func nullSourcesFor(m map[int64]*nullModel, fid int64) []nullSource {
	if m == nil || m[fid] == nil {
		return nil
	}
	return m[fid].sources
}
