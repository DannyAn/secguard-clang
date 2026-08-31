package planner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// RangeFilter drops divide-by-zero candidates whose divisor is provably non-zero
// via cross-assignment interval propagation (`d = 0; d = 1; x / d`) and
// cross-function return summaries (`x / get_count()` where get_count never
// returns zero). It is the consumer of the range_flow.go engine, moving
// divide-by-zero from a pure-syntax detector to a graph-assisted convergence
// stage.
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

	resolver := newReturnSummaryResolver(ctx, f.store, f.parser)
	flows := f.buildFlows(ctx, byFunc, resolver)

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
			// A direct call divisor (`x / get_count()`) has no bare-identifier
			// variable to flow-propagate, so resolve the callee's return summary
			// directly.
			if name := f.callDivisorName(ctx, c); name != "" && resolver.nonZeroReturn(name) {
				dropped = dismiss(dropped, c, f.Name(),
					fmt.Sprintf("divisor %s() provably returns non-zero at line %d", name, c.Line))
				continue
			}
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

// callDivisorName returns the callee name when the candidate's divisor is a
// direct call (`foo()`), else "".
func (f *RangeFilter) callDivisorName(ctx context.Context, c Candidate) string {
	event, err := f.store.GetEventByID(ctx, c.DerefEventID)
	if err != nil || event == nil {
		return ""
	}
	return callNameFromDivisorText(parseEventProps(event.Properties).Divisor)
}

// callNameFromDivisorText extracts the callee name from a divisor spelled as a
// call (`foo(...)`, possibly parenthesized). It returns "" for any other shape so
// a compound expression like `(a - b)` is never mistaken for a call.
var reCallDivisor = regexp.MustCompile(`^\s*\(*\s*([A-Za-z_]\w*)\s*\(`)

func callNameFromDivisorText(text string) string {
	m := reCallDivisor.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return ""
	}
	return m[1]
}

func (f *RangeFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate, resolver *returnSummaryResolver) map[int64]*rangeFlow {
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
		flows[fid] = analyzeRangesWithCalls(fn, body, resolver.callResult)
	}
	return flows
}
