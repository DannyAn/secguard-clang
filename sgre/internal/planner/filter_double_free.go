package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// DoubleFreeFilter converges the double-free stream with the same freed-state
// dataflow as the UAF lifetime filter: gen = first free(p), kill = p = <non-alias
// reassignment>, copy = p = q. A candidate is suppressed when the freed state
// from the first free no longer reaches the second free (the pointer was
// reassigned in between, so the second free frees a different block).
type DoubleFreeFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDoubleFreeFilter(store db.Store, p *parser.Parser, logger *log.Logger) *DoubleFreeFilter {
	return &DoubleFreeFilter{store: store, parser: p, logger: logger}
}

func (f *DoubleFreeFilter) Name() string { return "double_free_flow" }

func (f *DoubleFreeFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

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
		if !flow.reaching(c.VariableName, c.Line) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("variable %s is reassigned before the second free at line %d", c.VariableName, c.Line))
			continue
		}
		// The first-free state reaches the second free. It is a CERTAIN double-
		// free only when the first free reaches on every path (must); otherwise
		// it stays a suspicion for the AI to confirm.
		if flow.mustReaching(c.VariableName, c.Line) {
			c.SuspicionLevel = "confirmed"
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

func (f *DoubleFreeFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate) map[int64]*flowResult {
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
		// Seed the freed-state ONLY at each candidate's first-free site. The UAF
		// lifetime filter seeds every free site (loadFreeSites), but a double-free
		// analysis must NOT seed the second free too: seeding both makes the
		// second free "reach itself" via genAt and the filter never suppresses —
		// two mutually-exclusive frees (a guarded `free(p); return;` then a tail
		// `free(p)`) become a false confirmed double-free. Indirect frees have no
		// RELEASE edge, so their first_free also arrives via the detector's
		// event property here, exactly like a direct free.
		genByLine := make(map[int][]string)
		for _, c := range cs {
			event, err := f.store.GetEventByID(ctx, c.DerefEventID)
			if err != nil || event == nil {
				continue
			}
			var props struct {
				FirstFree int    `json:"first_free"`
				Variable  string `json:"variable"`
			}
			if json.Unmarshal([]byte(event.Properties), &props) != nil || props.FirstFree == 0 || props.Variable == "" {
				continue
			}
			if !freeAlreadySeeded(genByLine, props.FirstFree, props.Variable) {
				genByLine[props.FirstFree] = append(genByLine[props.FirstFree], props.Variable)
			}
		}

		killByLine := make(map[int][]string)
		forEachAssignment(body, func(lhs, rhs parser.Node) {
			if lhs.Kind() != "identifier" {
				return
			}
			if rhsVarName(rhs) == "" {
				killByLine[lhs.StartLine()] = append(killByLine[lhs.StartLine()], lhs.Text())
			}
		})

		// free(p) dangles every alias of p, so the first-free source also reaches
		// a later free(q) where q aliases p (q = p; free(p); free(q)).
		expandGenToAliases(genByLine, analyzer.loadAliases(ctx, []int64{fid})[fid])
		flows[fid] = analyzer.analyzeFlowMust(ctx, fn, body, root, genByLine, killByLine, false, false)
	}
	return flows
}
