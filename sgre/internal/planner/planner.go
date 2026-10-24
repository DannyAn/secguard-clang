package planner

import (
	"context"
	"fmt"
	"sort"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type Planner struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
	// callReachCache shares the call-graph reachability across all Plan()
	// calls, since every vulnerability type runs the call-reach filter over
	// the same graph.
	callReachCache *callReachCache
	// taintCache shares the interprocedural taint summaries across injection /
	// path-traversal / format-string, which otherwise each recompute the same
	// ~39s fixpoints (the dominant plan-stage cost).
	taintCache *taintSummaryCache
	// macro shares the macro-context detector (and its file-line cache) across
	// every Plan() call, so a file is read at most once per scan even though up
	// to 24 vuln types run Plan concurrently.
	macro *macroContextDetector
	// cfgCache memoizes per-function *graph.StmtCFG across every filter that
	// needs one. Without it, each filter that consumes CFG (nullable-source /
	// lifetime / double-free / uninit / range / range-oob / int-overflow /
	// contract-gap) rebuilt the same function's CFG independently — a 10×
	// waste on a redis-scale scan.
	cfgCache *graph.CFGCache
	// querier is the per-scan semantic-query facade (graph.Querier). Filters
	// that need an ad-hoc flow answer should call Querier() instead of
	// rebuilding a flow engine; the querier reuses the same cfgCache so the
	// per-function CFG is still built at most once.
	querier graph.Querier
}

func NewPlanner(store db.Store, p *parser.Parser, logger *log.Logger) *Planner {
	pl := &Planner{
		store:          store,
		parser:         p,
		logger:         logger,
		callReachCache: &callReachCache{},
		taintCache:     newTaintSummaryCache(store, p),
		macro:          newMacroContextDetector(),
		cfgCache:       graph.NewCFGCache(),
	}
	pl.querier = NewQuerier(store, p, pl.cfgCache)
	return pl
}

// NewPlannerWithCache shares cfgCache with an upstream stage (typically the
// evidence stage) so CFGs built during detection hit the cache during plan.
func NewPlannerWithCache(store db.Store, p *parser.Parser, logger *log.Logger, cfgCache *graph.CFGCache) *Planner {
	pl := NewPlanner(store, p, logger)
	if cfgCache != nil {
		pl.cfgCache = cfgCache
		pl.querier = NewQuerier(store, p, cfgCache)
	}
	return pl
}

// Querier returns the per-scan semantic-query facade. The instance is
// shareable across goroutines (its state is read-only after construction).
func (p *Planner) Querier() graph.Querier { return p.querier }

func (p *Planner) Plan(ctx context.Context, vulnType string) (*PlanResult, error) {
	spec, err := GetVulnTypeSpec(vulnType)
	if err != nil {
		return nil, err
	}

	// Share this Planner's CFG cache with every filter via ctx so that a
	// function's statement CFG is built at most once per scan (see the
	// cfgCache field comment).
	ctx = withCFGCache(ctx, p.cfgCache)

	// The macro-context detector needs the scan's function-definition names
	// BEFORE the filter chain runs (MacroUncertainFilter consults it): an
	// ALL_CAPS static function (POOL_SECT) is a definition, not a #define.
	// Idempotent and mutex-guarded, so concurrent per-type Plan() calls load
	// the set exactly once.
	p.macro.ensureDefinedFuncs(ctx, p.store)

	seed, routedAway, err := p.seedCandidatesByType(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("planner: seed: %w", err)
	}

	summary := PipelineSummary{
		SeedCount: len(seed),
		// Seed events this type routed to a sibling by event category. Recorded
		// in the summary (not only in the log) so the raw-event-to-candidate
		// reduction is auditable from `secguard plan`/the evidence package — a
		// dropped-flavor category can no longer look like "the detector emitted
		// nothing".
		SeedRoutedByCategory: routedAway,
	}

	filters, err := p.buildFilters(spec)
	if err != nil {
		return nil, err
	}
	// Uniformly inject the per-scan CFG cache into every filter that supports
	// it. Filters that do not build statement CFGs simply do not implement
	// SetCFGCache and are skipped by the type assertion.
	for _, f := range filters {
		if ca, ok := f.(interface{ SetCFGCache(*graph.CFGCache) }); ok {
			ca.SetCFGCache(p.cfgCache)
		}
	}

	candidates := seed
	shortCircuited := false
	var dismissed []Dismissed
	for i, filter := range filters {
		inputCount := len(candidates)
		if inputCount == 0 {
			// A filter emptied the list; record the remaining filters as
			// skipped so summary.Filters always has one entry per filter (the
			// shape stays consistent for consumers).
			shortCircuited = true
			for _, skipped := range filters[i:] {
				summary.Filters = append(summary.Filters, FilterStats{
					Name:        skipped.Name(),
					InputCount:  0,
					OutputCount: 0,
				})
			}
			break
		}

		filtered, dropped, err := filter.Apply(ctx, candidates)
		var filterErr string
		if err != nil {
			if p.logger != nil {
				p.logger.Warn("filter failed", "filter", filter.Name(), "error", err)
			}
			filtered = candidates
			dropped = nil
			filterErr = err.Error()
		} else {
			dismissed = append(dismissed, dropped...)
		}

		outputCount := len(filtered)
		summary.Filters = append(summary.Filters, FilterStats{
			Name:        filter.Name(),
			InputCount:  inputCount,
			OutputCount: outputCount,
			Error:       filterErr,
		})

		if p.logger != nil {
			p.logger.Info("filter applied", "filter", filter.Name(), "input", inputCount, "output", outputCount)
		}

		candidates = filtered
	}

	summary.ShortCircuited = shortCircuited
	summary.FinalCount = len(candidates)
	summary.Dropped = dismissed
	if len(dismissed) > 0 {
		summary.DroppedByReason = make(map[string]int)
		for _, d := range dismissed {
			summary.DroppedByReason[d.Filter]++
		}
	}

	candidates = deduplicateCandidates(candidates, spec)
	summary.DedupedCount = len(candidates)

	result := &PlanResult{
		VulnerabilityType: vulnType,
		Candidates:        make([]EvidenceItem, 0),
		Summary:           summary,
	}

	// Rank by risk so the AI processes highest-risk candidates first, but do
	// NOT truncate: every deduped candidate is handed to the AI for review.
	// The former max-candidates cap silently hid the tail (redis null-deref
	// 1060 deduped but only 200 surfaced). The AI reviews all of them, in
	// batches if its step budget requires.
	candidates = RankCandidates(ctx, candidates, p.store)

	// Batch-load the files the candidates reference ONCE, instead of issuing a
	// GetFileByID point query per candidate (an N+1 storm on high-volume types
	// like null-deref). seedCandidatesByType already batches its function/
	// location lookups; this closes the same gap on the file-path lookup.
	// A ListFiles failure must not be swallowed either: with an empty map every
	// candidate loses its Target.File, so downstream auto-confirm and per-finding
	// markdown silently drop the location — the same "defect without a location"
	// failure the batch-load below forbids. Fail the type instead.
	files, ferr := p.store.ListFiles(ctx)
	if ferr != nil {
		return nil, fmt.Errorf("planner: list files: %w", ferr)
	}
	filePathByID := make(map[int64]string, len(files))
	for _, f := range files {
		filePathByID[f.ID] = f.Path
	}

	// unchecked-return resolves the callee for the failure-contract proof;
	// null-deref for the call-result-deref null@malloc-fail verdict (the
	// callee's body decides whether its return can be NULL); double-free for
	// the conditional first-release helper (cond@<callee>) whose body decides
	// whether the first release is conditional.
	if spec.Name == "unchecked-return" || spec.Name == "null-deref" || spec.Name == "double-free" {
		if err := p.resolveCalleeDefs(ctx, candidates, filePathByID); err != nil {
			return nil, fmt.Errorf("planner: resolve callee definitions: %w", err)
		}
	}

	for _, c := range candidates {
		c.MacroContext = p.macro.hasMacroContext(filePathByID[c.FileID], c.Line)
		result.Candidates = append(result.Candidates, newEvidenceItem(c, spec, filePathByID[c.FileID]))
	}

	return result, nil
}

// resolveCalleeDefs fills CalleeDefFile/CalleeDefLine/CalleeDefEndLine/
// CalleeDefSignature on unchecked-return candidates by joining the callee name
// (APIName) against the function index. contract@unknown candidates put the
// burden of proof on the classifier ("prove the callee returns a failure
// sentinel or dismiss"), and the callee is frequently a static factory defined
// in ANOTHER file — the report embeds the StartLine..EndLine body under
// ## Callee Definition so the classifier never burns its source-READ budget on a
// body the index already knows. A batch ListFunctions failure fails the type
// (same fail-fast as the seed lookups); a callee simply missing from the index is
// legitimate (external/library function) and leaves the fields zero.
func (p *Planner) resolveCalleeDefs(ctx context.Context, candidates []Candidate, filePathByID map[int64]string) error {
	funcs, err := p.store.ListFunctions(ctx)
	if err != nil {
		return fmt.Errorf("list functions: %w", err)
	}
	defsByName := make(map[string]*db.Function, len(funcs))
	for _, fn := range funcs {
		if _, ok := defsByName[fn.Name]; !ok {
			defsByName[fn.Name] = fn
		}
	}
	for i := range candidates {
		c := &candidates[i]
		// null-deref call-result dereferences (`f()->field`, `*f()`) carry
		// the callee in CalleeName instead of APIName, so the same resolver
		// gives them an embedded ## Callee Definition for the
		// null@malloc-fail verdict. double-free's conditional first-release
		// helper (`cond@<callee>`) carries it in FirstCallee — its body decides
		// whether the release is conditional, so embed it the same way.
		name := c.APIName
		if name == "" {
			name = c.CalleeName
		}
		if name == "" {
			name = c.FirstCallee
		}
		if name == "" {
			continue
		}
		fn := defsByName[name]
		if fn == nil {
			continue
		}
		c.CalleeDefFile = filePathByID[fn.FileID]
		c.CalleeDefLine = fn.StartLine
		c.CalleeDefEndLine = fn.EndLine
		c.CalleeDefSignature = fn.Signature
		// double-free's SECOND release helper (the unconditional cleanup call
		// whose body decides "both frees on one path") gets its own def span so
		// the report embeds it beside the conditional first helper.
		if c.SecondCallee != "" {
			if sfn := defsByName[c.SecondCallee]; sfn != nil {
				c.SecondCalleeDefFile = filePathByID[sfn.FileID]
				c.SecondCalleeDefLine = sfn.StartLine
				c.SecondCalleeDefEndLine = sfn.EndLine
			}
		}
	}
	return nil
}

// seedCandidatesByType returns this type's seed candidates plus a count of the
// seed events it routed away by event category (see SeedRoutedByCategory). The
// second value is non-nil only when events were actually dropped by category.
func (p *Planner) seedCandidatesByType(ctx context.Context, spec *VulnTypeSpec) ([]Candidate, map[string]int, error) {
	events, err := p.store.ListEventsByType(ctx, spec.SeedEventType)
	if err != nil {
		return nil, nil, fmt.Errorf("seed candidates: %w", err)
	}

	// Batch-load the functions and locations the seed events reference, so a type
	// with thousands of events does not issue one point query per event (an N+1
	// storm across every registered vuln type). Lookups that miss just leave the
	// zero value.
	funcIDs := make([]int64, 0, len(events))
	locIDs := make([]int64, 0, len(events))
	for _, e := range events {
		if e.EntityID > 0 {
			funcIDs = append(funcIDs, e.EntityID)
		}
		if e.LocationID > 0 {
			locIDs = append(locIDs, e.LocationID)
		}
	}
	// A batch load failure must not be swallowed: with nil maps every seed
	// candidate loses its FunctionName/FileID/Line, so the finding would be
	// written with a zero location — a security tool reporting a defect without
	// a location is worse than reporting nothing. Fail the type instead.
	funcsByID, err := p.store.ListFunctionsByIDs(ctx, funcIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("seed candidates: list functions: %w", err)
	}
	locsByID, err := p.store.ListLocationsByIDs(ctx, locIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("seed candidates: list locations: %w", err)
	}

	var candidates []Candidate
	droppedByCategory := 0
	// droppedCategories counts the seed events this type routed away BY event
	// category. Several types share one seed event (BUFFER_ACCESS feeds both
	// buffer-overflow and out-of-bounds), so a type legitimately drops the other
	// flavor's events; the map is what makes the log say which categories those
	// were instead of echoing the type's own allow-list.
	droppedCategories := map[string]int{}
	for _, e := range events {
		props := parseEventProps(e.Properties)

		funcName := ""
		fileID := int64(0)
		funcSignature := ""
		funcStartLine := 0
		funcEndLine := 0
		if fn := funcsByID[e.EntityID]; fn != nil {
			funcName = fn.Name
			fileID = fn.FileID
			funcSignature = fn.Signature
			funcStartLine = fn.StartLine
			funcEndLine = fn.EndLine
		}

		line := 0
		if loc := locsByID[e.LocationID]; loc != nil {
			line = loc.Line
			// A file-scope event (e.g. a hardcoded-secret global with no
			// enclosing function, so EntityID == 0) has no function to supply
			// the file, but its location does. Fall back to the location's file
			// so a function-less candidate is never emitted with an empty
			// Target.File (which would make auto-confirm re-flow it to AI and
			// per-finding markdown drop the location).
			if fileID == 0 {
				fileID = loc.FileID
			}
		}

		// The variable is the primary identity for dedup and variable-level
		// analysis. Fall back to the expression only for display/dedup of
		// types that carry no variable (e.g. integer-overflow, format-string).
		if len(spec.Categories) > 0 && !containsString(spec.Categories, props.Category) {
			droppedByCategory++
			droppedCategories[props.Category]++
			continue
		}

		varName := props.Variable
		if varName == "" {
			varName = props.Expression
		}

		// The API name is the called function (or the registry API for the
		// RegSetValueEx branch), kept distinct from the variable so that
		// SafeFunctionFilter can do exact lookups rather than substring
		// matching against expression text.
		apiName := props.Function
		if apiName == "" {
			apiName = props.API
		}

		// Default the suspicion to the type-level tier, then let a per-category
		// override (detector-proved categories) or a later flow filter (which
		// upgrades to "confirmed" when the graph proves the pattern) refine it.
		suspicion := spec.DefaultSuspicion
		if spec.CategoryConfidence != nil {
			if override := spec.CategoryConfidence[props.Category]; override != "" {
				suspicion = override
			}
		}
		if props.Tautology == "dead_branch" && suspicion == "confirmed" {
			suspicion = "suspected"
		}

		candidates = append(candidates, Candidate{
			DerefEventID:            e.ID,
			FunctionID:              e.EntityID,
			FunctionName:            funcName,
			VariableName:            varName,
			Expression:              props.Expression,
			APIName:                 apiName,
			Category:                props.Category,
			LocationID:              e.LocationID,
			FileID:                  fileID,
			Line:                    line,
			NonNullable:             props.NonNullable == "true",
			IsTypeExpr:              props.IsTypeExpr == "true",
			IsCallResultDeref:       props.IsCallResultDeref == "true",
			ContractKnown:           props.ContractKnown == "true",
			Consumed:                props.Consumed,
			CalleeName:              props.Callee,
			SuspicionLevel:          suspicion,
			DeclLine:                props.DeclLine,
			Origin:                  props.Origin,
			FieldPath:               props.FieldPath,
			InitWrite:               props.InitWrite,
			InitWriteLine:           int(props.InitWriteLine),
			Array:                   props.Array,
			Index:                   props.Index,
			Size:                    int(props.Size),
			IndexSource:             props.IndexSource,
			CapacitySymbol:          props.CapacitySymbol,
			ElemField:               props.ElemField,
			Escape:                  props.Escape,
			EscapeDeref:             props.EscapeDeref,
			ExpectedType:            props.Expected,
			ActualType:              props.Actual,
			CastType:                props.Cast,
			FunctionSignature:       funcSignature,
			FuncStartLine:           funcStartLine,
			FuncEndLine:             funcEndLine,
			LHSKind:                 props.LHSKind,
			RHSKind:                 props.RHSKind,
			SubRHSInfluenced:        props.RHSInfluenced == "true",
			SubSink:                 props.Sink,
			Subject:                 props.Subject,
			Sanitizer:               props.Sanitizer,
			CountField:              props.CountField,
			UseLine:                 props.UseLine,
			Missing:                 props.Missing,
			EvidenceKind:            props.EvidenceKind,
			GuardLine:               int(props.GuardLine),
			FreeLine:                props.FreeLine,
			FirstFree:               props.FirstFree,
			SecondFree:              props.SecondFree,
			MayFree:                 props.MayFree == "true",
			FirstCallee:             props.FirstCallee,
			SecondCallee:            props.SecondCallee,
			Victims:                 props.Victims,
			DefiniteLeak:            props.Definite == "true",
			LeakEscapeKind:          props.EscapeKind,
			LeakFreeLines:           props.FreeLines,
			LeakFreeMismatch:        props.FreeMismatch,
			LeakTransferConditional: props.TransferConditional,
			LeakFreeOnBorrow:        props.BorrowFree,
			ThreadFunctions:         props.ThreadFunctions,
			ThreadInstances:         int(props.ThreadInstances),
			WriteLine:               int(props.WriteLine),
			CopySize:                props.CopySize,
			DstCapacity:             props.DstCapacity,
			SizeArgument:            props.SizeArgument,
			SrcCapacity:             int(props.SrcCapacity),
			MutexA:                  props.MutexA,
			MutexB:                  props.MutexB,
			ReverseFunc:             props.ReverseFunc,
			SecretValue:             props.Value,
			CheckFunction:           props.CheckFunc,
			UseFunction:             props.UseFunc,
			CheckPathArg:            props.PathArg,
			Mutex:                   props.Mutex,
			LockLine:                int(props.LockLine),
			UnlockLine:              int(props.UnlockLine),
			CryptoReason:            props.Reason,
			CryptoKeySize:           int(props.KeySize),
			FormatArg:               props.FormatArg,
			PathExpr:                props.Path,
			SubLHSInfluenced:        props.LHSInfluenced == "true",
		})
	}

	// A detector/registry category-string drift is otherwise silent: the events
	// exist, but the Categories filter drops them and the type reads "0
	// candidates" as if the detector had emitted nothing. Warn ONLY when a
	// dropped category is claimed by no registered type that shares this seed
	// event — that is the real drift. The previous version warned whenever a type
	// dropped all its events AND logged spec.Categories (the type's OWN allow-list),
	// so a benign cross-type route read as "the allowed categories were dropped":
	// out-of-bounds dropping the write-flavored BUFFER_ACCESS events (which
	// buffer-overflow owns) produced a phantom OOB false-negative alarm.
	if p.logger != nil && droppedByCategory > 0 {
		orphan := p.unroutedCategories(spec, droppedCategories)
		if len(orphan) > 0 {
			p.logger.Warn("unrouted seed event categories: no vuln type claims them",
				"vuln_type", spec.Name, "seed_event_type", spec.SeedEventType,
				"events", len(events), "orphan_categories", orphan,
				"allowed_categories", spec.Categories)
		} else {
			p.logger.Debug("seed events routed away by category to sibling vuln types",
				"vuln_type", spec.Name, "events", len(events),
				"dropped_by_category", droppedCategories, "candidates", len(candidates))
		}
	}

	if droppedByCategory == 0 {
		return candidates, nil, nil
	}
	return candidates, droppedCategories, nil
}

// unroutedCategories returns the subset of dropped that no registered vuln type
// other than spec claims. Categories claimed only by spec itself cannot appear
// here (spec would have kept them), so the result is exactly the events lost to
// a detector/registry naming drift rather than to legitimate cross-type routing.
func (p *Planner) unroutedCategories(spec *VulnTypeSpec, dropped map[string]int) map[string]int {
	routed := make(map[string]bool)
	for _, name := range AllVulnTypes() {
		if name == spec.Name {
			continue
		}
		other, err := GetVulnTypeSpec(name)
		if err != nil || other.SeedEventType != spec.SeedEventType {
			continue
		}
		for _, c := range other.Categories {
			routed[c] = true
		}
	}
	orphan := make(map[string]int)
	for cat, n := range dropped {
		if !routed[cat] {
			orphan[cat] = n
		}
	}
	return orphan
}

// suspicionRank orders suspicion tiers so a dedup merge can never let a
// lower-confidence candidate overwrite a higher-confidence one.
func suspicionRank(s string) int {
	switch s {
	case "confirmed":
		return 3
	case "suspected":
		return 2
	case "possible":
		return 1
	default:
		return 0
	}
}

func deduplicateCandidates(candidates []Candidate, spec *VulnTypeSpec) []Candidate {
	seen := make(map[string]int)
	result := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		// Variable-converged types keep ONE candidate per (function, variable)
		// but must carry every sink line: a nullable pointer dereferenced on
		// several paths is one root cause whose blast radius is the full sink
		// list, and the classifier/fix suggestion needs all of them.
		if spec.ConvergeByVariable {
			c.DerefLines = appendUniqueLine(c.DerefLines, c.Line)
		}
		key := spec.dedupKey(c)
		idx, ok := seen[key]
		if !ok {
			seen[key] = len(result)
			result = append(result, c)
			continue
		}
		keep := &result[idx]
		// Prefer the higher-confidence tier (confirmed > suspected > possible)
		// so a detector-proved candidate is never downgraded to a needsReview
		// twin; when the tier ties, keep the earliest line so merged findings
		// anchor at the source (e.g. sprintf) rather than the sink
		// (sqlite3_exec).
		replace := suspicionRank(c.SuspicionLevel) > suspicionRank(keep.SuspicionLevel) ||
			(suspicionRank(c.SuspicionLevel) == suspicionRank(keep.SuspicionLevel) && c.Line < keep.Line)
		if spec.ConvergeByVariable {
			for _, l := range c.DerefLines {
				keep.DerefLines = appendUniqueLine(keep.DerefLines, l)
			}
		}
		if replace {
			lines := keep.DerefLines
			*keep = c
			keep.DerefLines = lines
		}
	}
	for i := range result {
		if len(result[i].DerefLines) > 1 {
			sort.Ints(result[i].DerefLines)
		}
	}
	return result
}

// appendUniqueLine adds line to a sorted-on-return sink list, ignoring the
// unknown (0) line and duplicates.
func appendUniqueLine(lines []int, line int) []int {
	if line <= 0 {
		return lines
	}
	for _, l := range lines {
		if l == line {
			return lines
		}
	}
	return append(lines, line)
}

func (spec *VulnTypeSpec) dedupKey(c Candidate) string {
	if spec.ConvergeKey != nil {
		return spec.ConvergeKey(c)
	}
	if spec.ConvergeByVariable {
		// One finding per (function, variable): a single nullable variable
		// dereferenced at many sites is one defect, not many.
		return fmt.Sprintf("%d:%s:%s", c.FileID, c.FunctionName, c.VariableName)
	}
	return fmt.Sprintf("%d:%d:%s:%s", c.FileID, c.Line, c.FunctionName, c.VariableName)
}
