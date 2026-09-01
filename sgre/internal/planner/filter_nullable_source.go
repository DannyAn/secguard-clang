package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/macros"
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

	// Batch-load the candidate functions and their files ONCE, so the pre-scan
	// and the analyze loop below do not each issue N+1 point queries.
	fnByID, _ := f.store.ListFunctionsByIDs(ctx, funcIDs)
	fileByID := map[int64]*db.File{}
	if files, ferr := f.store.ListFiles(ctx); ferr == nil {
		for _, fl := range files {
			fileByID[fl.ID] = fl
		}
	}

	cache := newFileParseCache(f.parser)
	analyzer.macroWrites = collectMacroWrites(cache, fileByID)
	analyzer.iterMacros = mergedIterMacros()

	// Pre-scan: parse each candidate function's body and collect the callees
	// assigned to a variable (`p = f()`). retNullable is ONLY consumed by
	// callResultNullSources for exactly those assignments, so when no candidate
	// function has any such assignment, computing the whole-program
	// return-nullability is wasted work and is skipped entirely — it was the
	// dominant cost of nullable_source over a large codebase (an eager fixpoint
	// over every function regardless of whether the result is used).
	assignedCallees := map[string]bool{}
	for fid := range byFunc {
		fn := fnByID[fid]
		if fn == nil {
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, _ := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		forEachAssignment(body, func(lhs, rhs parser.Node) {
			if assignTargetName(lhs) == "" {
				return
			}
			if name := rhsCallName(rhs); name != "" {
				assignedCallees[name] = true
			}
		})
	}

	// Inter-procedural return-nullability: which functions can return NULL.
	// Only computed when a candidate function actually assigns a call result to
	// a variable (`p = f()`). Fail-open on error: keep candidates.
	retNullable := map[string]bool{}
	if len(assignedCallees) > 0 {
		var err error
		retNullable, err = f.computeRetNullable(ctx, models, assignedCallees)
		if err != nil {
			retNullable = map[string]bool{}
		}
	}

	results := make(map[int64]*flowResult, len(byFunc))
	for fid := range byFunc {
		fn := fnByID[fid]
		if fn == nil {
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
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
// possibly-null pointer. It is scoped to the caller-influenced closure of
// seedNames (the callees a candidate function assigns to a variable via
// `p = f()`): those are the ONLY names callResultNullSources can ever consult,
// so analysing the whole program is wasted work. Within that closure it is a
// monotone fixpoint seeded from function_summary.return_nullable (literal
// `return NULL`), then extended to functions returning an allocator, a pointer
// parameter, a variable with a reaching may-null source, or a call to another
// nullable-returning function.
func (f *NullableSourceFilter) computeRetNullable(ctx context.Context, models map[int64]*nullModel, seedNames map[string]bool) (map[string]bool, error) {
	retNullable := make(map[string]bool)
	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("ret nullable summary: list functions: %w", err)
	}

	// name -> functions (same-name overloads are merged conservatively: if any
	// one returns nullable, the name is treated as nullable).
	funcsByName := make(map[string][]*db.Function, len(funcs))
	for _, fn := range funcs {
		funcsByName[fn.Name] = append(funcsByName[fn.Name], fn)
	}

	// Batch-load summaries and files once, avoiding per-function point queries.
	allFnIDs := make([]int64, 0, len(funcs))
	for _, fn := range funcs {
		allFnIDs = append(allFnIDs, fn.ID)
	}
	summariesByID, _ := f.store.ListSummariesByFunctionIDs(ctx, allFnIDs)
	fileByID := make(map[int64]*db.File)
	if files, ferr := f.store.ListFiles(ctx); ferr == nil {
		for _, fl := range files {
			fileByID[fl.ID] = fl
		}
	}

	cache := newFileParseCache(f.parser)

	// Transitive closure: from seedNames, follow `p = f()` assignments to find
	// every function the return-nullability query can reach.
	needNames := make(map[string]bool, len(seedNames))
	queue := make([]string, 0, len(seedNames))
	for n := range seedNames {
		if !needNames[n] {
			needNames[n] = true
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		for _, fn := range funcsByName[name] {
			file := fileByID[fn.FileID]
			if file == nil {
				continue
			}
			body, _ := cache.get(file, fn)
			if body.Kind() != "compound_statement" {
				continue
			}
			forEachAssignment(body, func(lhs, rhs parser.Node) {
				if assignTargetName(lhs) == "" {
					return
				}
				if callee := rhsCallName(rhs); callee != "" && !needNames[callee] {
					needNames[callee] = true
					queue = append(queue, callee)
				}
			})
		}
	}

	type funcInfo struct {
		fn     *db.Function
		body   parser.Node
		root   parser.Node
		params map[string]int
		srcs   []nullSource
	}
	infos := make([]funcInfo, 0, len(needNames))
	seen := make(map[int64]bool)
	for name := range needNames {
		for _, fn := range funcsByName[name] {
			if seen[fn.ID] {
				continue
			}
			seen[fn.ID] = true
			file := fileByID[fn.FileID]
			if file == nil {
				continue
			}
			body, root := cache.get(file, fn)
			if body.Kind() != "compound_statement" {
				continue
			}

			// Seed from the detector's function_summary (literal `return NULL`/`0`).
			if sum := summariesByID[fn.ID]; sum != nil && sum.ReturnNullable {
				retNullable[fn.Name] = true
				continue
			}

			// Pre-filter: a function whose return statements can only yield a
			// non-pointer literal can never return a NULL pointer, so skip it.
			if !mayReturnPointer(body) {
				continue
			}

			var srcs []nullSource
			if models != nil && models[fn.ID] != nil {
				srcs = models[fn.ID].sources
			}
			infos = append(infos, funcInfo{fn: fn, body: body, root: root, params: paramsOf(fn, root), srcs: srcs})
		}
	}

	allIDs := make([]int64, 0, len(infos))
	for i := range infos {
		allIDs = append(allIDs, infos[i].fn.ID)
	}
	analyzer := newFlowAnalyzer(f.store, f.parser)
	analyzer.dfgCopies = analyzer.loadDFGCopies(ctx, allIDs)
	analyzer.macroWrites = collectMacroWrites(cache, fileByID)
	analyzer.iterMacros = mergedIterMacros()

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

// collectMacroWrites merges per-file macro write-summaries across the whole scan
// tree so a macro defined in a .h header (SAMPLE_Scan, POOL_FOR, ...) is visible
// at call sites in every .c source. The per-file WriteSummaries of the source
// file cannot see the header's definition, so a macro-initialized iterator
// would be misreported as null-deref. The parse cache makes this cheap.
func collectMacroWrites(cache *fileParseCache, fileByID map[int64]*db.File) map[string]macros.WriteSummary {
	var perFile []map[string]macros.WriteSummary
	for _, file := range fileByID {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		perFile = append(perFile, macros.WriteSummaries(root))
	}
	return macros.MergeWriteSummaries(perFile...)
}

// mergedIterMacros combines the built-in iterator-macro knowledge base
// (apikb.IteratorMacros, covering standard list_for_each_entry & friends) with
// project-specific iterator macros declared in secguard.toml [iterator_macros].
// The merged map is what addOutputParamKills consults to kill the iterator
// argument's null source at a call site whose macro definition is outside the
// scan tree.
func mergedIterMacros() map[string][]int {
	out := make(map[string][]int, len(apikb.IteratorMacros))
	for k, v := range apikb.IteratorMacros {
		out[k] = v
	}
	for k, v := range config.Load().IteratorMacroArgs() {
		out[k] = v
	}
	return out
}
