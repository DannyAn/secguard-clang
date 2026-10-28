package planner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// RangeFilter is the divide-by-zero convergence stage. It drops candidates whose
// divisor is provably non-zero (via cross-assignment interval propagation
// `d = 0; d = 1; x / d`, and cross-function return summaries `x / get_count()`
// where get_count never returns zero), and it upgrades to "confirmed" the one
// shape it can resolve deterministically: a provably-zero divisor (`d = 0;
// x / d`, a certain divide-by-zero). A config-field/global divisor is NOT
// auto-confirmed (see Apply): its zero-invariant is only "not proven locally",
// not "proven possibly-zero", so it stays suspected for the AI. Confirmed
// candidates are handed to the auto-confirm pass instead of the AI agent.
type RangeFilter struct {
	store    db.Store
	parser   *parser.Parser
	logger   *log.Logger
	cfgCache *graph.CFGCache
}

// SetCFGCache is the uniform-injection entrypoint used by Planner.Plan.
func (f *RangeFilter) SetCFGCache(c *graph.CFGCache) { f.cfgCache = c }

func NewRangeFilter(store db.Store, p *parser.Parser, logger *log.Logger) *RangeFilter {
	return &RangeFilter{store: store, parser: p, logger: logger}
}

func (f *RangeFilter) Name() string { return "range" }

func (f *RangeFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	// A config-field/global divisor is NOT auto-confirmed here: its zero-invariant
	// is only "not proven locally", not "proven possibly-zero", and a field like
	// graph->gran_time is usually non-zero by construction. Auto-confirming would
	// emit a confirmed false positive the AI can never correct, so it stays
	// suspected and the AI judges it (the same rule as hardcoded-secret).
	if f.parser == nil {
		return candidates, nil, nil
	}

	// Batch-load every candidate's event once: divisor / isDefinitelyZeroEvent /
	// callDivisorName previously issued one GetEventByID per candidate.
	eventIDs := make([]int64, 0, len(candidates))
	seen := make(map[int64]bool, len(candidates))
	for _, c := range candidates {
		if !seen[c.DerefEventID] {
			seen[c.DerefEventID] = true
			eventIDs = append(eventIDs, c.DerefEventID)
		}
	}
	eventsByID, err := f.store.ListEventsByIDs(ctx, eventIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("range: load events: %w", err)
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}

	resolver := newReturnSummaryResolver(ctx, f.store, f.parser)
	invariants := buildGlobalInvariants(ctx, f.store, f.parser, resolver)
	flows := f.buildFlows(ctx, byFunc, resolver)

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		// A divisor the detector proved is exactly zero (literal `x/0` or a
		// zero-valued constant symbol) is a certain divide-by-zero: auto-confirm
		// it before the interval analysis so it never reaches the AI agent.
		if f.isDefinitelyZeroEvent(eventsByID, c) {
			c.SuspicionLevel = "confirmed"
			kept = append(kept, c)
			continue
		}

		flow := flows[c.FunctionID]
		if flow == nil {
			kept = append(kept, c)
			continue
		}
		divisor := f.divisor(eventsByID, c)
		if divisor == "" {
			// A direct call divisor (`x / get_count()`) has no bare-identifier
			// variable to flow-propagate, so resolve the callee's return summary
			// directly.
			if name := f.callDivisorName(eventsByID, c); name != "" && resolver.nonZeroReturn(name) {
				dropped = dismiss(dropped, c, f.Name(),
					fmt.Sprintf("divisor %s() provably returns non-zero at line %d", name, c.Line))
				continue
			}
			// A field-chain divisor (`graph->gran_time`) is stripped to "" by
			// bareIdentVar, so the invariants.NonZero check below is never
			// reached. Check the raw divisor text here so a field proven
			// non-zero by a cross-function invariant is dismissed.
			if raw := f.rawDivisor(eventsByID, c); raw != "" && invariants.NonZero(raw) {
				dropped = dismiss(dropped, c, f.Name(),
					fmt.Sprintf("divisor %s is proven non-zero by a cross-function invariant at line %d", raw, c.Line))
				continue
			}
			kept = append(kept, c)
			continue
		}
		// A global/field divisor proven non-zero by a cross-function
		// invariant (registered after a zero-check guard, backfilled with
		// a default, etc.) is safe.
		if invariants.NonZero(divisor) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("divisor %s is proven non-zero by a cross-function invariant at line %d", divisor, c.Line))
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
		} else if !r.isTop() {
			// The engine has a tighter-than-top fact but cannot exclude 0
			// (e.g. `d ∈ [0, 5]`). Hand the interval to the classifier —
			// whether 0 is reachable within it is exactly what it must judge.
			c.DivisorInterval = r.String()
		}
		kept = append(kept, c)
	}

	// Parameter zero-propagation over the call graph: a divisor that is a function
	// PARAMETER is unknown to the function-local interval, so trace it to its
	// direct callers. Some caller passing a literal zero makes it a certain
	// divide-by-zero (confirm); every direct caller passing a non-zero constant
	// makes it safe (dismiss); otherwise it stays suspected.
	sites := newCallSiteResolver(ctx, f.store, f.parser)
	cache := newFileParseCache(f.parser)
	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	finalKept := make([]Candidate, 0, len(kept))
	for _, c := range kept {
		if c.SuspicionLevel == "confirmed" {
			finalKept = append(finalKept, c)
			continue
		}
		fn := fnByID[c.FunctionID]
		if fn == nil {
			finalKept = append(finalKept, c)
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			finalKept = append(finalKept, c)
			continue
		}
		divisor := f.divisor(eventsByID, c)
		if divisor == "" {
			finalKept = append(finalKept, c)
			continue
		}
		idx, ok := cache.paramsFor(file, fn)[divisor]
		if !ok {
			finalKept = append(finalKept, c)
			continue
		}
		zero, allNonZero := sites.paramVerdict(fn.Name, fn.FileID, idx, fn.IsStatic)
		// A non-static function has external callers outside the scan tree (or
		// callers reached via a function pointer), so "every direct caller passes
		// non-zero" cannot be asserted for it — keep it suspected rather than
		// wrongly dismissing a genuine divide-by-zero (DBZ-11).
		if allNonZero && !fn.IsStatic {
			allNonZero = false
		}
		switch {
		case zero:
			c.SuspicionLevel = "confirmed"
			finalKept = append(finalKept, c)
		case allNonZero:
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("divisor %s is a parameter every direct caller passes non-zero at line %d", divisor, c.Line))
		default:
			// Unsettled: some caller passes a non-constant. Record the
			// middle-ground verdict so the classifier can judge the unchecked
			// callers by name instead of re-deriving the call graph.
			if n, nz := sites.paramSummary(fn.Name, fn.FileID, idx, fn.IsStatic); n > 0 {
				c.DivisorCallers = fmt.Sprintf("%d direct call sites, %d pass non-zero constants", n, nz)
			}
			finalKept = append(finalKept, c)
		}
	}
	return finalKept, dropped, nil
}

// divisor returns the bare-identifier divisor of a divide-by-zero candidate, or
// "" when the divisor is a complex expression the interval engine cannot prove.
func (f *RangeFilter) divisor(eventsByID map[int64]*db.SecurityEvent, c Candidate) string {
	event := eventsByID[c.DerefEventID]
	if event == nil {
		return ""
	}
	return bareIdentVar(parseEventProps(event.Properties).Divisor)
}

// rawDivisor returns the trimmed divisor text of a divide-by-zero candidate
// without bare-identifier stripping, preserving field chains (`graph->gran_time`)
// and call expressions (`get_count()`) for invariant matching.
func (f *RangeFilter) rawDivisor(eventsByID map[int64]*db.SecurityEvent, c Candidate) string {
	event := eventsByID[c.DerefEventID]
	if event == nil {
		return ""
	}
	return strings.TrimSpace(parseEventProps(event.Properties).Divisor)
}

// isDefinitelyZeroEvent reports whether the candidate's event carries an explicit
// "definitely_zero" marker from the detector — a literal `x/0` or a zero-valued
// constant symbol, a certain divide-by-zero.
func (f *RangeFilter) isDefinitelyZeroEvent(eventsByID map[int64]*db.SecurityEvent, c Candidate) bool {
	event := eventsByID[c.DerefEventID]
	if event == nil {
		return false
	}
	return parseEventProps(event.Properties).DefinitelyZero == "true"
}

// callDivisorName returns the callee name when the candidate's divisor is a
// direct call (`foo()`), else "".
func (f *RangeFilter) callDivisorName(eventsByID map[int64]*db.SecurityEvent, c Candidate) string {
	event := eventsByID[c.DerefEventID]
	if event == nil {
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
		flows[fid] = analyzeRangesWithCalls(f.cfgCache, fn, body, resolver.callResult)
	}
	return flows
}

// reFieldChain matches a pure struct/object field-access chain (`graph->gran_time`,
// `s.field`, `a.b.c`, `p->next->val`). It deliberately does NOT match compound
// expressions (`(p->a - p->b)`), array subscripts (`arr[i]`), dereferences
// (`*p`), or calls (`foo()`), which stay suspected for the AI agent.
var reFieldChain = regexp.MustCompile(`^[A-Za-z_]\w*\s*(?:(?:->|\.)\s*[A-Za-z_]\w*)+$`)

// divisorShape classifies a divide-by-zero divisor's syntactic shape so the
// candidate index's Hint column can tell the AI agent what it is looking at
// without opening the evidence file. `bare` (a plain identifier) is the one the
// classifier can settle from the Source column alone; `field`/`global` stay
// suspected for the AI; `call`/`compound` need the Code Context.
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

// DeclaredProofs implements ProofRegistrar.
func (f *RangeFilter) DeclaredProofs() []Proof {
	return []Proof{
		{
			Class:    ProofClassInterval,
			Rule:     "divisor-always-zero",
			Evidence: "interval analysis proves the divisor is exactly zero at the division site",
			TestRef:  "TestRangeFilter",
		},
	}
}
