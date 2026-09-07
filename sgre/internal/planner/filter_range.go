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

// RangeFilter is the divide-by-zero convergence stage. It drops candidates whose
// divisor is provably non-zero (via cross-assignment interval propagation
// `d = 0; d = 1; x / d`, and cross-function return summaries `x / get_count()`
// where get_count never returns zero), and it upgrades to "confirmed" the two
// shapes it can resolve deterministically: a config-field/global divisor
// (`x / graph->gran_time`, a defensive-check gap) and a provably-zero divisor
// (`d = 0; x / d`, a certain divide-by-zero). Confirmed candidates are handed to
// the auto-confirm pass instead of the AI agent.
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
	// A config-field divisor (a struct/object field or module global) is a
	// "missing defensive check" the pipeline can confirm deterministically: the
	// value's zero-invariant belongs to object/global initialization, not the
	// arithmetic use site, so no local guard can (or should) re-prove it. The
	// detector has already suppressed the locally-provable-safe shapes (literal,
	// sizeof, const, guard, early-return), so what remains is a genuine defect
	// worth surfacing to the engineer — it should be auto-confirmed, not handed
	// to the AI agent (which cannot judge a cross-file init invariant anyway).
	// The check is purely syntactic, so it runs even without a parser.
	for i := range candidates {
		if isConfigFieldDivisor(candidates[i].VariableName) {
			candidates[i].SuspicionLevel = "confirmed"
		}
	}

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
		r := flow.at(divisor, c.Line)
		if r.isNonZero() {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("divisor %s is provably non-zero at line %d", divisor, c.Line))
			continue
		}
		if r.isDefinitelyZero() {
			// `d = 0; x / d` — the interval analysis proves the divisor is
			// exactly zero at the division, a certain divide-by-zero.
			c.SuspicionLevel = "confirmed"
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

// reFieldChain matches a pure struct/object field-access chain (`graph->gran_time`,
// `s.field`, `a.b.c`, `p->next->val`). It deliberately does NOT match compound
// expressions (`(p->a - p->b)`), array subscripts (`arr[i]`), dereferences
// (`*p`), or calls (`foo()`), which stay suspected for the AI agent.
var reFieldChain = regexp.MustCompile(`^[A-Za-z_]\w*\s*(?:(?:->|\.)\s*[A-Za-z_]\w*)+$`)

// isConfigFieldDivisor reports whether a divide-by-zero divisor is an external
// state value whose zero-invariant is established outside the use-site function:
// a struct/object field chain (`graph->gran_time`, `hdr->elements`,
// `hash->bkt_size`) or a module-global variable (`g_df_thread_count`). Because
// the value is initialized elsewhere and no local guard re-proves it, the
// unguarded division is a genuine defensive-check gap the pipeline confirms
// deterministically rather than deferring to the AI agent.
func isConfigFieldDivisor(divisor string) bool {
	s := strings.TrimSpace(divisor)
	if reFieldChain.MatchString(s) {
		return true
	}
	return strings.HasPrefix(s, "g_") && bareIdentVar(s) != ""
}

// divisorShape classifies a divide-by-zero divisor's syntactic shape so the
// candidate index's Hint column can tell the AI agent what it is looking at
// without opening the evidence file. `bare` (a plain identifier) is the one the
// classifier can settle from the Source column alone; `field`/`global` are
// auto-confirmed by the pipeline; `call`/`compound` need the Code Context.
func divisorShape(divisor string) string {
	s := strings.TrimSpace(divisor)
	switch {
	case s == "":
		return ""
	case reFieldChain.MatchString(s):
		return "field"
	case strings.HasPrefix(s, "g_") && bareIdentVar(s) != "":
		return "global"
	case bareIdentVar(s) != "":
		return "bare"
	case reCallDivisor.MatchString(s):
		return "call"
	default:
		return "compound"
	}
}
