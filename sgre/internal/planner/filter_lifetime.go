package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type LifetimeFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewLifetimeFilter(store db.Store, p *parser.Parser, logger *log.Logger) *LifetimeFilter {
	return &LifetimeFilter{store: store, parser: p, logger: logger}
}

func (f *LifetimeFilter) Name() string { return "lifetime" }

func (f *LifetimeFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	// Group by function so each function's free/reassignment dataflow is built
	// once. gen = free(p); kill = p = <anything non-alias> (reassignment clears
	// the freed state); copy = p = q (alias inherits the freed state).
	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}

	flows := f.buildFlows(ctx, byFunc)

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		flow := flows[c.FunctionID]
		if flow == nil {
			kept = append(kept, c)
			continue
		}
		useLine := c.Line
		if !flow.reaching(c.VariableName, useLine) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("variable %s is reassigned or the free does not reach the use at line %d", c.VariableName, useLine))
			continue
		}
		// The freed state reaches the use. It is a CERTAIN use-after-free only
		// when the free reaches on every path (must); a free confined to one of
		// several branches (may-only) stays a suspicion for the AI to confirm.
		if flow.mustReaching(c.VariableName, useLine) {
			c.SuspicionLevel = "confirmed"
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

func (f *LifetimeFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate) map[int64]*flowResult {
	flows := make(map[int64]*flowResult, len(byFunc))
	cache := newFileParseCache(f.parser)
	for fid, cs := range byFunc {
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

		analyzer := newFlowAnalyzer(f.store, f.parser)
		// Direct free sites come from the graph's RELEASE edges (release_fn ==
		// "free"); indirect frees (a callee frees a parameter) have no RELEASE
		// edge, so those are seeded from the detector's event properties.
		genByLine := analyzer.loadFreeSites(ctx, []int64{fid})[fid]
		if genByLine == nil {
			genByLine = make(map[int][]string)
		}
		for _, c := range cs {
			event, err := f.store.GetEventByID(ctx, c.DerefEventID)
			if err != nil || event == nil {
				continue
			}
			var props struct {
				FreeLine int    `json:"free_line"`
				Variable string `json:"variable"`
				Indirect bool   `json:"indirect"`
			}
			if json.Unmarshal([]byte(event.Properties), &props) != nil || props.FreeLine == 0 || props.Variable == "" {
				continue
			}
			// Seed from the event only when it is an indirect free (a callee
			// frees a parameter — no RELEASE edge) or when the graph layer was
			// not built (no RELEASE edge for this direct free site).
			if props.Indirect || !freeAlreadySeeded(genByLine, props.FreeLine, props.Variable) {
				genByLine[props.FreeLine] = append(genByLine[props.FreeLine], props.Variable)
			}
		}

		// kill: a whole-variable reassignment (p = <non-alias>) clears the freed
		// state. p = q is a copy handled by the flow engine's AST copy step.
		killByLine := make(map[int][]string)
		forEachAssignment(body, func(lhs, rhs parser.Node) {
			if lhs.Kind() != "identifier" {
				return
			}
			if rhsVarName(rhs) == "" {
				killByLine[lhs.StartLine()] = append(killByLine[lhs.StartLine()], lhs.Text())
			}
		})

		// free(p) dangles every alias of p, so propagate the freed source through
		// the ALIAS edges the graph layer persists (q = p; free(p); *q).
		expandGenToAliases(genByLine, analyzer.loadAliases(ctx, []int64{fid})[fid])
		flows[fid] = analyzer.analyzeFlowMust(ctx, fn, body, root, genByLine, killByLine, false, false)
	}
	return flows
}
