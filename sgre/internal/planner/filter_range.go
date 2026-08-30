package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// RangeFilter drops divide-by-zero candidates whose divisor is provably non-zero
// via cross-assignment interval propagation (`d = 0; d = 1; x / d`). It is the
// first consumer of the range_flow.go engine, moving divide-by-zero from a
// pure-syntax detector to a graph-assisted convergence stage.
type RangeFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewRangeFilter(store db.Store, p *parser.Parser, logger *log.Logger) *RangeFilter {
	return &RangeFilter{store: store, parser: p, logger: logger}
}

func (f *RangeFilter) Name() string { return "range" }

func (f *RangeFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
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
		divisor := f.divisor(ctx, c)
		if divisor == "" {
			kept = append(kept, c)
			continue
		}
		if flow.at(divisor, c.Line).isNonZero() {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("divisor %s is provably non-zero at line %d", divisor, c.Line))
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

// divisor returns the bare-identifier divisor of a divide-by-zero candidate, or
// "" when the divisor is a complex expression the interval engine cannot prove.
func (f *RangeFilter) divisor(ctx context.Context, c Candidate) string {
	event, err := f.store.GetEventByID(ctx, c.DerefEventID)
	if err != nil || event == nil {
		return ""
	}
	return bareIdentVar(parseEventProps(event.Properties).Divisor)
}

func (f *RangeFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate) map[int64]*rangeFlow {
	flows := make(map[int64]*rangeFlow, len(byFunc))
	cache := newFileParseCache(f.parser)
	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
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
		flows[fid] = analyzeRanges(fn, body)
	}
	return flows
}
