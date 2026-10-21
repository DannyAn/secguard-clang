package planner

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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

	flowResults, retNullable, definedNames, synthByFunc, retGuards, err := f.buildFlowResults(ctx, byFunc, models)
	if err != nil {
		return nil, nil, err
	}

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		if c.NonNullable {
			dropped = dismiss(dropped, c, f.Name(), "variable is non-nullable")
			continue
		}

		// A direct dereference of a function-call result (`f()->field`, `*f()`,
		// `f()[i]`) has no tracked variable, so the per-variable reaching
		// analysis below cannot resolve it. Apply the same three-state return
		// model used by detectExternalCall: known non-null → dropped; known
		// nullable libc/POSIX → confirmed; a DEFINED callee resolves through the
		// inter-procedural retNullable set; an unknown external callee stays
		// suspected (open world, fail-open).
		if c.IsCallResultDeref {
			if apikb.IsNonNullReturning(c.CalleeName) {
				dropped = dismiss(dropped, c, f.Name(),
					fmt.Sprintf("callee %s is declared non-null", c.CalleeName))
				continue
			}
			if apikb.IsKnownNullableReturn(c.CalleeName) {
				c.HasNullableSource = true
				c.SuspicionLevel = "confirmed"
				c.NullOriginTier = "malloc-fail"
				c.NullableOriginName = c.CalleeName
			} else if retNullable[c.CalleeName] == retNullProven {
				// A defined callee whose body PROVABLY returns NULL (a literal
				// NULL path, an allocator result, or a proven callee chain):
				// the same textbook tier as an allocator — a proven-nullable
				// origin, auto-confirmed. Its definition is embedded for the
				// re-review loop.
				c.HasNullableSource = true
				c.SuspicionLevel = "confirmed"
				c.NullOriginTier = "malloc-fail"
				c.NullableOriginName = c.CalleeName
			} else if retNullable[c.CalleeName] == retNullAssumed {
				// The callee's nullability is a FAIL-OPEN assumption (it
				// returns a parameter, a field, or an unknown call): keep it
				// suspected, labelled assumed-return so the AI judges the
				// assumption instead of rubber-stamping a "proven" prior.
				c.HasNullableSource = true
				c.SuspicionLevel = "suspected"
				c.NullOriginTier = "assumed-return"
				c.NullableOriginName = c.CalleeName
			} else if !definedNames[c.CalleeName] {
				c.HasNullableSource = true
				c.SuspicionLevel = "suspected"
				c.NullOriginTier = "external-unknown"
			} else {
				dropped = dismiss(dropped, c, f.Name(),
					fmt.Sprintf("callee %s does not return a nullable value (inter-procedural retNullable analysis)", c.CalleeName))
				continue
			}
			kept = append(kept, c)
			continue
		}

		fm := flowResults[c.FunctionID]
		if fm != nil {
			if fm.reaching(c.VariableName, c.Line) {
				c.HasNullableSource = true
				c.HasDefiniteNull = fm.reachingDefinite(c.VariableName, c.Line)
				c.SourceLine = fm.sourceLine(c.VariableName, c.Line)
				c.CallerNullDetail = callerNullDetail(models[c.FunctionID], c.VariableName)
				if models[c.FunctionID].onlyUnprovenCallerNullSources(c.VariableName) ||
					(!c.HasDefiniteNull && fm.contract.paramAliasUnproven(c.VariableName, c.Line, models[c.FunctionID])) {
					dropped = dismiss(dropped, c, f.Name(),
						fmt.Sprintf("parameter %s has no proven nullable caller argument", c.VariableName))
					continue
				}
				if c.SourceLine > 0 && !c.HasDefiniteNull && fm.weakGuardAt(c.VariableName, c.Line) {
					dropped = dismiss(dropped, c, f.Name(),
						fmt.Sprintf("dereference of %s is short-circuit null-guarded in its condition", c.VariableName))
					continue
				}
				// A value derived (directly, through a cast, or through an unknown
				// external accessor) from an opaque void* parameter the function
				// never null-checks is non-null by the caller contract of IPC /
				// callback handlers. An allocator / known maybe-null source and an
				// explicit null are excluded, so a genuine possible-null value is
				// still reported.
				if !c.HasDefiniteNull && !models[c.FunctionID].onlyCertainNullableSources(c.VariableName) &&
					fm.contract.contractDerived(c.VariableName, c.Line, models[c.FunctionID]) {
					dropped = dismiss(dropped, c, f.Name(),
						fmt.Sprintf("variable %s derives from a void* parameter dereferenced by non-null contract", c.VariableName))
					continue
				}
				// The "checked grow then access" idiom: the container was grown
				// under a failure guard, so an accessor fetch at a strictly lower
				// index is in range and returns a valid interior pointer. The
				// fail-open external_call source is an analyzer limitation, not a
				// candidate the AI should spend a verdict on.
				if !c.HasDefiniteNull && !models[c.FunctionID].onlyCertainNullableSources(c.VariableName) &&
					fm.contract.growThenAccess(c.VariableName, c.Line, models[c.FunctionID]) {
					dropped = dismiss(dropped, c, f.Name(),
						fmt.Sprintf("variable %s is re-fetched from an accessor after a checked grow on the same container", c.VariableName))
					continue
				}
				// Inter-procedural guard contracts on the callee (see
				// retNullGuardContract): a conditional-nonnull getter (R2)
				// returns NULL only under a null check of a pointer
				// parameter and otherwise an address-of value; a strip-style
				// helper (R3) returns NULL only under a parameter null check
				// or a strlen(p) >= len overflow check and otherwise forwards
				// a parameter. When every identifier argument at the
				// assignment line has no reaching null source (the call sits
				// inside the argument's own null guard, which the flow
				// analysis already honours) and no argument is an opaque
				// shape, the parameter-null paths are unreachable; for R3 the
				// overflow path additionally needs the caller's conjunctive
				// early return `strlen(arg) != 0 && lhs == NULL` (an overflow
				// implies strlen(arg) >= len > 0, so the guard fires first)
				// and a provably positive length argument.
				if !c.HasDefiniteNull && retGuards != nil {
					if src := synthSourceAt(synthByFunc[c.FunctionID], c.VariableName, c.Line); src != nil && !src.argUnsafe {
						if g := retGuards[src.origin]; g != nil {
							argsSafe := true
							for _, av := range src.argVarNames {
								if fm.reaching(av, src.line) {
									argsSafe = false
									break
								}
							}
							if argsSafe && g.paramNullOnly {
								dropped = dismiss(dropped, c, f.Name(),
									fmt.Sprintf("callee %s returns null only for a null argument; argument is non-null at line %d", src.origin, src.line))
								continue
							}
							if argsSafe && g.overflowArg >= 0 && overflowGuardMutex(fm, src, g, c.Line) {
								dropped = dismiss(dropped, c, f.Name(),
									fmt.Sprintf("callee %s returns null only for a null or overflowing argument; caller guards strlen != 0 with %s == NULL before line %d", src.origin, c.VariableName, c.Line))
								continue
							}
						}
					}
				}
				// Layering: reflect the must/may tier in the suspicion label so
				// the AI budgets effort by certainty. A DEFINITE null source
				// (p = NULL) reaching on every path is a certain null-deref →
				// confirmed; a possible-null source (malloc/function return) is
				// only maybe-null → suspected, so the AI reasons about it instead
				// of rubber-stamping a "confirmed" prior.
				//
				// Exceptions: an ALLOCATOR source (malloc/calloc/realloc) or a
				// known maybe-null libc/POSIX function (strchr/fopen/getenv/...)
				// inherently returns NULL, and a planner-synthesized `p = f()`
				// whose callee the fixpoint graded PROVEN has a concrete NULL
				// witness in its body — all textbook CWE-476 regardless of path,
				// kept confirmed rather than downgraded. Only a fail-open source
				// (unknown external call, assumed callee) stays suspected.
				synthCallee := synthCalleeAt(synthByFunc[c.FunctionID], c.VariableName, c.Line)
				synthProven := synthCallee != "" && retNullable[synthCallee] == retNullProven
				if !c.HasDefiniteNull && !models[c.FunctionID].onlyCertainNullableSources(c.VariableName) && !synthProven {
					c.SuspicionLevel = "suspected"
				}
				// The nullable-origin tier feeds the null@<tier> hint token:
				// the classifier's job differs per tier (cfg-proof and
				// malloc-fail are machine-proved textbook CWE-476; caller-arg
				// needs the caller's contract; assumed-return is a fail-open
				// assumption on an in-scan callee; external-unknown is a fail-open
				// assumption on an out-of-scan callee).
				switch {
				case c.HasDefiniteNull:
					c.NullOriginTier = "cfg-proof"
				case models[c.FunctionID].onlyCertainNullableSources(c.VariableName):
					c.NullOriginTier = "malloc-fail"
					c.NullableOriginName = models[c.FunctionID].certainNullableOrigin(c.VariableName)
				case c.CallerNullDetail != "":
					c.NullOriginTier = "caller-arg"
				case models[c.FunctionID].hasOpaqueSource(c.VariableName):
					// An opaque_param / opaque_field_read source: the value's
					// nullability comes from a contract the scan tree cannot
					// see (an external caller's argument, an externally-defined
					// struct's field value). Fail-open: suspected, the AI
					// judges the contract.
					c.NullOriginTier = "opaque-origin"
				case synthCallee != "":
					// An in-scan callee the inter-procedural fixpoint graded:
					// proven (a concrete NULL witness in the body) keeps the
					// textbook malloc-fail tier and the auto-confirm above;
					// assumed (fail-open) is labelled so the AI judges the
					// assumption. CalleeName makes resolveCalleeDefs embed the
					// callee body under ## Callee Definition, so the AI never
					// opens the source to see why it can return NULL.
					c.CalleeName = synthCallee
					c.NullableOriginName = synthCallee
					if synthProven {
						c.NullOriginTier = "malloc-fail"
					} else {
						c.NullOriginTier = "assumed-return"
					}
				default:
					c.NullOriginTier = "external-unknown"
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
		if models[c.FunctionID].onlyUnprovenCallerNullSources(c.VariableName) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("parameter %s has no proven nullable caller argument", c.VariableName))
			continue
		}
		if models[c.FunctionID].hasSource(c.VariableName, c.Line) {
			c.HasNullableSource = true
			c.SuspicionLevel = "suspected"
			// The line-order fallback cannot classify the origin — the
			// conservative tier tells the AI this is an unproven assumption.
			c.NullOriginTier = "external-unknown"
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
// falls back to the line-order heuristic). The returned retNullable set is the
// inter-procedural "which functions can return NULL" map, consumed by Apply for
// call-result dereferences (`f()->field`, `*f()`, `f()[i]`) that have no
// tracked variable to feed the per-variable reaching analysis. The returned
// synthByFunc map carries, per candidate function, the planner-synthesized
// `p = f()` null sources whose callee the fixpoint proved nullable — Apply
// reads them back to classify such variables as malloc-fail (proven-nullable
// in-scan callee) instead of external-unknown (fail-open assumption).
func (f *NullableSourceFilter) buildFlowResults(ctx context.Context, byFunc map[int64][]Candidate, models map[int64]*nullModel) (map[int64]*flowResult, map[string]retNullability, map[string]bool, map[int64][]nullSource, map[string]*retNullGuard, error) {
	if f.parser == nil {
		return nil, nil, nil, nil, nil, nil
	}

	funcIDs := make([]int64, 0, len(byFunc))
	for fid := range byFunc {
		funcIDs = append(funcIDs, fid)
	}

	analyzer := newFlowAnalyzer(f.store, f.parser)
	analyzer.dfgCopies = analyzer.loadDFGCopies(ctx, funcIDs)

	// Batch-load the candidate functions and their files ONCE, so the pre-scan
	// and the analyze loop below do not each issue N+1 point queries.
	fnByID, err := f.store.ListFunctionsByIDs(ctx, funcIDs)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("nullable source: list functions: %w", err)
	}
	fileByID := map[int64]*db.File{}
	if files, ferr := f.store.ListFiles(ctx); ferr == nil {
		for _, fl := range files {
			fileByID[fl.ID] = fl
		}
	}

	cache := newFileParseCache(f.parser)
	analyzer.macroWrites = collectMacroWrites(cache, fileByID)
	analyzer.iterMacros = mergedIterMacros()
	// The guard model needs the whole-tree predicate-helper and guard-macro
	// summaries (a helper/macro may be defined in a .h header). A ListFunctions
	// failure degrades to an empty helper summary (helper guards become false
	// positives, never a hidden null-deref), matching the fail-open convention.
	var allFuncs []*db.Function
	if funcs, ferr := f.store.ListFunctions(ctx); ferr == nil {
		allFuncs = funcs
	}
	analyzer.helperParams = collectNullCheckHelpers(cache, allFuncs, fileByID)
	analyzer.macroGuards = collectMacroGuards(cache, fileByID)

	// Pre-scan: parse each candidate function's body and collect the callees
	// assigned to a variable (`p = f()`). retNullable is ONLY consumed by
	// callResultNullSources for exactly those assignments, so when no candidate
	// function has any such assignment, computing the whole-program
	// return-nullability is wasted work and is skipped entirely — it was the
	// dominant cost of nullable_source over a large codebase (an eager fixpoint
	// over every function regardless of whether the result is used).
	assignedCallees := map[string]bool{}
	// Call-result dereferences (`f()->field`, `*f()`, `f()[i]`) carry no
	// `p = f()` assignment, so the body scan below never sees their callee.
	// Pull the callee names directly from the candidates so retNullable
	// covers them.
	for _, cs := range byFunc {
		for _, c := range cs {
			if c.IsCallResultDeref && c.CalleeName != "" {
				assignedCallees[c.CalleeName] = true
			}
		}
	}
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

	// Inter-procedural return-nullability: which functions can return NULL, and
	// which names are DEFINED in the scan (vs external). Only computed when a
	// candidate function actually assigns a call result to a variable
	// (`p = f()`) or directly dereferences one (`f()->field`). Fail-open on
	// error: keep candidates.
	retNullable := map[string]retNullability{}
	definedNames := map[string]bool{}
	retGuards := map[string]*retNullGuard{}
	if len(assignedCallees) > 0 {
		var err error
		retNullable, definedNames, retGuards, err = f.computeRetNullable(ctx, models, assignedCallees)
		if err != nil {
			retNullable = map[string]retNullability{}
			definedNames = map[string]bool{}
			retGuards = map[string]*retNullGuard{}
		}
	}

	synthByFunc := make(map[int64][]nullSource, len(byFunc))
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
		// Split sources: caller_null sources (origin "caller_null") are seeded at
		// the CFG ENTRY (a parameter has no body statement to hang a line-keyed
		// gen on), while intra-procedural sources stay line-keyed. An
		// opaque_param source (a pointer parameter of a function with zero
		// in-tree callers) is seeded at the entry the same way — never definite.
		// An opaque_field_read source seeds at the entry when its line sits at
		// or before the function header (the chained-dereference intermediate
		// form: the field value is possibly-null from birth, there is no
		// assignment statement to hang the gen on) and stays line-keyed when it
		// is an actual assignment (`tree = (T *)(resp->group_data)`).
		sources := nullSourcesFor(models, fid)
		var entrySeeds map[string]bool
		var definiteEntrySeeds map[string]bool
		var lineSources []nullSource
		for _, s := range sources {
			birthField := s.origin == "opaque_field_read" && s.line <= fn.StartLine
			if s.origin == "caller_null" || s.origin == "opaque_param" || birthField {
				if entrySeeds == nil {
					entrySeeds = map[string]bool{}
				}
				entrySeeds[s.variable] = true
				// A caller passing a literal NULL is a CERTAIN null at entry, so it
				// seeds the must-null tier (confirmed) rather than only the may tier.
				if s.definite {
					if definiteEntrySeeds == nil {
						definiteEntrySeeds = map[string]bool{}
					}
					definiteEntrySeeds[s.variable] = true
				}
			} else {
				lineSources = append(lineSources, s)
			}
		}
		synth := callResultNullSources(body, retNullable)
		lineSources = append(lineSources, synth...)
		if len(synth) > 0 {
			synthByFunc[fid] = synth
		}
		analyzer.entrySeeds = entrySeeds
		analyzer.definiteEntrySeeds = definiteEntrySeeds
		res := analyzer.analyzeFunction(ctx, fn, body, root, lineSources)
		if res != nil {
			res.contract = buildContractCtx(fn, root, body)
		}
		results[fid] = res
	}
	return results, retNullable, definedNames, synthByFunc, retGuards, nil
}

// synthSourceAt returns the planner-synthesized `p = f()` null source whose
// assignment to variable is closest before line — the same selection rule as
// synthCalleeAt, but carrying the full source (origin, assignment line, and
// call-site argument facts) so the conditional-nonnull-getter dismissal can
// check the arguments against the reaching analysis.
func synthSourceAt(synth []nullSource, variable string, line int) *nullSource {
	var best *nullSource
	for i := range synth {
		s := &synth[i]
		if s.variable != variable || s.line <= 0 || s.line > line {
			continue
		}
		if best == nil || s.line >= best.line {
			best = s
		}
	}
	return best
}

// retNullGuard is the inter-procedural NULL-return contract of one callee
// name, computed from its body by retNullGuardContract.
type retNullGuard struct {
	// paramNullOnly (the R2 conditional-nonnull getter): every NULL return
	// sits under a null check of a pointer parameter and every other return
	// is an address-of value, so a call site with non-null arguments gets a
	// non-null result.
	paramNullOnly bool
	// overflowArg / overflowLen (the R3 strip-style helper): NULL returns sit
	// under a parameter null check or a strlen(p) >= len overflow check —
	// one consistent p and len across the body — and every other return
	// forwards a parameter or takes an address. overflowArg is the index of
	// the strlen-checked parameter; overflowLen the index of the length
	// parameter, or -1 when the length is a sizeof/positive literal inside
	// the callee itself (already provably positive). Both are -1 when the
	// contract carries no overflow branch.
	overflowArg int
	overflowLen int
}

// retNullGuardContract classifies how a callee can return NULL. It returns
// nil when the body has no qualifying contract, so the true positives behind
// real nullable getters are preserved: a getter whose NULL path depends on
// anything but a parameter null check or a strlen overflow check (an id
// range check, global state) does not qualify, nor does a function with a
// non-parameter, non-address-of, non-forwarding success return.
func retNullGuardContract(body parser.Node, params map[string]int) *retNullGuard {
	var nullReturns, otherReturns, addrReturns int
	var hasOverflow, allParamNull = false, true
	ovArg, ovLen := -1, -1
	for _, ret := range body.FindAll("return_statement") {
		kids := ret.NamedChildren()
		if len(kids) == 0 {
			continue
		}
		expr := kids[0]
		if parser.IsNullOperand(expr) {
			nullReturns++
			if returnGuardedByParamNull(ret, params) {
				continue
			}
			argIdx, lenIdx, ok := returnGuardedByStrlenOverflow(ret, params)
			if !ok {
				return nil
			}
			if hasOverflow && (ovArg != argIdx || ovLen != lenIdx) {
				return nil
			}
			if !hasOverflow {
				ovArg, ovLen, hasOverflow = argIdx, lenIdx, true
			}
			allParamNull = false
			continue
		}
		otherReturns++
		if isAddressOfExpr(expr) {
			addrReturns++
			continue
		}
		if name := identifierName(expr); name == "" {
			return nil
		} else if _, ok := params[name]; !ok {
			return nil
		}
	}
	// The contract needs at least one guarded NULL return (the relaxation
	// target) and one non-null return (otherwise the callee returns NULL on
	// every path, argument or not).
	if nullReturns == 0 || otherReturns == 0 {
		return nil
	}
	if allParamNull && addrReturns == otherReturns {
		return &retNullGuard{paramNullOnly: true, overflowArg: -1, overflowLen: -1}
	}
	if hasOverflow {
		return &retNullGuard{overflowArg: ovArg, overflowLen: ovLen}
	}
	return nil
}

// identifierName returns the plain identifier behind node, peeling
// parentheses and casts, or "" for anything else.
func identifierName(n parser.Node) string {
	switch n.Kind() {
	case "identifier":
		return n.Text()
	case "parenthesized_expression", "cast_expression":
		kids := n.NamedChildren()
		if len(kids) == 1 {
			return identifierName(kids[0])
		}
	}
	return ""
}

// returnGuardedByParamNull reports whether a `return NULL` statement sits on
// a path guarded by a null check of one of the given parameters: walking the
// if ancestors whose consequence contains the return, the path condition
// must establish some parameter null.
func returnGuardedByParamNull(ret parser.Node, params map[string]int) bool {
	for p := ret.Parent(); p != nil; p = p.Parent() {
		if p.Kind() != "if_statement" {
			continue
		}
		cons := p.ChildByFieldName("consequence")
		if cons == nil || !nodeContainsLine(*cons, ret.StartLine()) {
			continue
		}
		cond := p.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		for _, v := range trueNullVars(*cond) {
			if _, ok := params[v]; ok {
				return true
			}
		}
	}
	return false
}

// nodeContainsLine reports whether node's line range covers line.
func nodeContainsLine(n parser.Node, line int) bool {
	return n.StartLine() <= line && line <= n.EndLine()
}

// trueNullVars returns the variables a condition establishes as NULL when it
// evaluates TRUE — the direction needed to prove a `return NULL` path is
// entered only under a parameter null check. A top-level `||` qualifies only
// when EVERY operand is a pure null check (`p == NULL`, `!p`): the condition
// being true then guarantees at least one operand's variable is null. A `&&`
// contributes the union of its operands' facts. `p != NULL` true is a
// NON-null fact and never qualifies; comparisons like `id >= MAX` establish
// nothing about nullness.
func trueNullVars(cond parser.Node) []string {
	switch cond.Kind() {
	case "parenthesized_expression", "cast_expression":
		for _, c := range cond.NamedChildren() {
			if vars := trueNullVars(c); len(vars) > 0 {
				return vars
			}
		}
		return nil
	case "binary_expression":
		switch parser.BinaryOperator(cond) {
		case "||":
			var vars []string
			for _, child := range cond.NamedChildren() {
				v := pureNullCheckVar(child)
				if v == "" {
					return nil
				}
				vars = append(vars, v)
			}
			return vars
		case "&&":
			var vars []string
			for _, child := range cond.NamedChildren() {
				vars = append(vars, trueNullVars(child)...)
			}
			return vars
		case "==":
			if v := pureNullCheckVar(cond); v != "" {
				return []string{v}
			}
		}
		return nil
	case "unary_expression":
		if v := pureNullCheckVar(cond); v != "" {
			return []string{v}
		}
	}
	return nil
}

// pureNullCheckVar returns the variable when cond is a pure null check whose
// TRUE direction establishes that variable null (`p == NULL`, `NULL == p`,
// `!p`, possibly parenthesized), or "". The dual parser helpers distinguish
// the polarity: a pure null check has a false-direction non-null fact and no
// true-direction non-null fact. For the `==` form the null side must be a
// null LITERAL (NULL / nullptr), never the integer zero: `p == 0` on an
// integer parameter is a value comparison (`id == 0`, an id-range getter),
// not a null-pointer check — accepting it would qualify the getter for the
// parameter-null contract and dismiss its true-positive consumers.
func pureNullCheckVar(cond parser.Node) string {
	if cond.Kind() == "binary_expression" && parser.BinaryOperator(cond) == "==" {
		kids := cond.NamedChildren()
		if len(kids) == 2 && !isNullLiteralIdent(kids[0]) && !isNullLiteralIdent(kids[1]) {
			return ""
		}
	}
	checked := parser.NullCheckedVars(cond)
	if len(checked) == 0 || len(parser.GuardedNonnullVars(cond)) > 0 {
		return ""
	}
	return checked[0]
}

// isNullLiteralIdent reports whether node is an unambiguous null literal in a
// COMPARISON context — the `null` kind, the NULL / nullptr identifiers, or a
// parenthesized null literal. The integer zero is deliberately excluded:
// unlike the assignment-context matcher in null_flow.go (`p = (T*)0` is a
// null pointer), a bare `x == 0` comparison is a value test (`id == 0`, an
// id-range getter), not a null-pointer check.
func isNullLiteralIdent(n parser.Node) bool {
	switch n.Kind() {
	case "null":
		return true
	case "identifier":
		return n.Text() == "NULL" || n.Text() == "nullptr"
	case "parenthesized_expression":
		kids := n.NamedChildren()
		return len(kids) == 1 && isNullLiteralIdent(kids[0])
	}
	return false
}

// returnGuardedByStrlenOverflow reports whether a `return NULL` statement
// sits on a path guarded by a strlen overflow check of a parameter
// (`strlen(p) >= len`), and which parameter indices play p and len. lenIdx
// is -1 when the length side is a sizeof/positive literal in the callee
// itself (already provably positive). Only conjuncts of the guarding
// condition qualify: the condition being true must imply the overflow.
func returnGuardedByStrlenOverflow(ret parser.Node, params map[string]int) (int, int, bool) {
	for p := ret.Parent(); p != nil; p = p.Parent() {
		if p.Kind() != "if_statement" {
			continue
		}
		cons := p.ChildByFieldName("consequence")
		if cons == nil || !nodeContainsLine(*cons, ret.StartLine()) {
			continue
		}
		cond := p.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		var conjuncts []parser.Node
		collectConjuncts(*cond, &conjuncts)
		for _, cj := range conjuncts {
			if argIdx, lenIdx, ok := strlenOverflowTest(cj, params); ok {
				return argIdx, lenIdx, true
			}
		}
	}
	return 0, 0, false
}

// collectConjuncts flattens the `&&` conjuncts of a condition (peeling
// parentheses) into out. `||` operands are NOT split: a disjunction being
// true does not imply any single operand.
func collectConjuncts(cond parser.Node, out *[]parser.Node) {
	switch {
	case cond.Kind() == "parenthesized_expression":
		for _, c := range cond.NamedChildren() {
			collectConjuncts(c, out)
		}
		return
	case cond.Kind() == "binary_expression" && parser.BinaryOperator(cond) == "&&":
		for _, c := range cond.NamedChildren() {
			collectConjuncts(c, out)
		}
		return
	}
	*out = append(*out, cond)
}

// strlenOverflowTest matches one conjunct as `strlen(p) >= len` (or the
// mirrored `len <= strlen(p)`, or the strict > / < forms): the TRUE
// direction establishes strlen(p) >= len. p must be a parameter; len must be
// a parameter or a sizeof/positive literal.
func strlenOverflowTest(cond parser.Node, params map[string]int) (int, int, bool) {
	if cond.Kind() != "binary_expression" {
		return 0, 0, false
	}
	kids := cond.NamedChildren()
	if len(kids) != 2 {
		return 0, 0, false
	}
	var strlenSide, lenSide parser.Node
	switch parser.BinaryOperator(cond) {
	case ">=", ">":
		strlenSide, lenSide = kids[0], kids[1]
	case "<=", "<":
		strlenSide, lenSide = kids[1], kids[0]
	default:
		return 0, 0, false
	}
	argIdx, ok := strlenCallParamIndex(strlenSide, params)
	if !ok {
		return 0, 0, false
	}
	lenIdx, ok := overflowLenIndex(lenSide, params)
	if !ok {
		return 0, 0, false
	}
	return argIdx, lenIdx, true
}

// strlenCallParamIndex matches node as `strlen(p)` with p a parameter,
// returning p's index.
func strlenCallParamIndex(n parser.Node, params map[string]int) (int, bool) {
	if n.Kind() != "call_expression" {
		return 0, false
	}
	callee := n.ChildByFieldName("function")
	if callee == nil || callee.Kind() != "identifier" || callee.Text() != "strlen" {
		return 0, false
	}
	args := callArgs(n)
	if len(args) != 1 {
		return 0, false
	}
	name := identifierName(args[0])
	if name == "" {
		return 0, false
	}
	idx, ok := params[name]
	if !ok {
		return 0, false
	}
	return idx, true
}

// overflowLenIndex resolves the length side of an overflow test: a parameter
// index, or -1 for a sizeof/positive literal (provably positive in the
// callee itself). Anything else fails the contract.
func overflowLenIndex(n parser.Node, params map[string]int) (int, bool) {
	if name := identifierName(n); name != "" {
		if idx, ok := params[name]; ok {
			return idx, true
		}
		return 0, false
	}
	if isPositiveSizeExpr(n) {
		return -1, true
	}
	return 0, false
}

// isPositiveSizeExpr reports whether node is a sizeof expression or a
// positive integer literal — a provably positive length.
func isPositiveSizeExpr(n parser.Node) bool {
	switch n.Kind() {
	case "sizeof_expression":
		return true
	case "number_literal":
		v, err := strconv.ParseInt(strings.TrimSpace(n.Text()), 0, 64)
		return err == nil && v > 0
	}
	return false
}

// overflowGuardMutex discharges the strlen-overflow NULL path of an R3
// contract at one call site: the overflow argument is a plain identifier,
// the length argument (when the callee takes it as a parameter) is provably
// positive, and the caller early-returns under the conjunctive guard
// `strlen(arg) != 0 && lhs == NULL` between the assignment and the
// dereference. An overflow implies strlen(arg) >= len > 0, i.e.
// strlen(arg) != 0, so the guard fires before the dereference is reached.
func overflowGuardMutex(fm *flowResult, src *nullSource, g *retNullGuard, derefLine int) bool {
	if fm == nil || fm.contract == nil || fm.contract.body.Kind() == "" {
		return false
	}
	if g.overflowArg >= len(src.argInfo) {
		return false
	}
	arg := src.argInfo[g.overflowArg]
	if arg.kind != argIdent {
		return false
	}
	if g.overflowLen >= 0 {
		if g.overflowLen >= len(src.argInfo) {
			return false
		}
		if la := src.argInfo[g.overflowLen]; la.kind != argSizeof && la.kind != argPosLit {
			return false
		}
	}
	return callerStrlenMutexGuard(fm.contract.body, arg.name, src.variable, src.line, derefLine)
}

// callerStrlenMutexGuard finds, between the assignment line (exclusive) and
// the dereference line (inclusive), an early-return if whose condition is a
// conjunction of a `strlen(argName) != 0` (or > 0 / mirrored) test and an
// `lhsVar == NULL` test.
func callerStrlenMutexGuard(body parser.Node, argName, lhsVar string, fromLine, toLine int) bool {
	for _, ifn := range body.FindAll("if_statement") {
		line := ifn.StartLine()
		if line <= fromLine || line > toLine {
			continue
		}
		cons := ifn.ChildByFieldName("consequence")
		if cons == nil || len(cons.FindAll("return_statement")) == 0 {
			continue
		}
		cond := ifn.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		var conjuncts []parser.Node
		collectConjuncts(*cond, &conjuncts)
		strlenOK, nullOK := false, false
		for _, cj := range conjuncts {
			if isStrlenNonEmptyTest(cj, argName) {
				strlenOK = true
			}
			if pureNullCheckVar(cj) == lhsVar && lhsVar != "" {
				nullOK = true
			}
		}
		if strlenOK && nullOK {
			return true
		}
	}
	return false
}

// isStrlenNonEmptyTest matches cond as `strlen(argName) != 0`, `> 0`, or the
// literal-mirrored `0 != strlen(argName)` / `0 < strlen(argName)` — the TRUE
// direction establishes strlen(argName) > 0. A `strlen(arg) < 0` /
// `0 > strlen(arg)` shape is rejected: it is always false for size_t.
func isStrlenNonEmptyTest(cond parser.Node, argName string) bool {
	if cond.Kind() != "binary_expression" {
		return false
	}
	kids := cond.NamedChildren()
	if len(kids) != 2 {
		return false
	}
	zero := func(n parser.Node) bool {
		return n.Kind() == "number_literal" && strings.TrimSpace(n.Text()) == "0"
	}
	switch parser.BinaryOperator(cond) {
	case "!=":
		return (isStrlenCallOn(kids[0], argName) && zero(kids[1])) ||
			(zero(kids[0]) && isStrlenCallOn(kids[1], argName))
	case ">":
		return isStrlenCallOn(kids[0], argName) && zero(kids[1])
	case "<":
		return zero(kids[0]) && isStrlenCallOn(kids[1], argName)
	}
	return false
}

// isStrlenCallOn matches node as `strlen(argName)`.
func isStrlenCallOn(n parser.Node, argName string) bool {
	if n.Kind() != "call_expression" {
		return false
	}
	callee := n.ChildByFieldName("function")
	if callee == nil || callee.Kind() != "identifier" || callee.Text() != "strlen" {
		return false
	}
	args := callArgs(n)
	return len(args) == 1 && identifierName(args[0]) == argName
}

// synthCalleeAt returns the callee name of the planner-synthesized `p = f()`
// null source for variable that reaches the dereference line — the assignment
// closest before line (multiple assignments of different callees to the same
// variable take the latest one, matching the flow engine's kill semantics).
// The origin of such a source is the callee name, and callResultNullSources
// only synthesizes it when retNullable already PROVED that callee can return
// NULL, so a non-empty return is a proven-nullable in-scan origin.
func synthCalleeAt(synth []nullSource, variable string, line int) string {
	best := ""
	bestLine := 0
	for _, s := range synth {
		if s.variable != variable || s.line <= 0 || s.line > line {
			continue
		}
		if best == "" || s.line >= bestLine {
			best = s.origin
			bestLine = s.line
		}
	}
	return best
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
func (f *NullableSourceFilter) computeRetNullable(ctx context.Context, models map[int64]*nullModel, seedNames map[string]bool) (map[string]retNullability, map[string]bool, map[string]*retNullGuard, error) {
	// The fixpoint runs on a graded map: any non-notNull value means
	// "nullable" for the iteration; the final collapse below re-grades each
	// nullable name from the per-definition assumed evidence.
	retNullable := make(map[string]retNullability)
	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ret nullable summary: list functions: %w", err)
	}

	// name -> functions (same-name overloads are merged conservatively: if any
	// one returns nullable, the name is treated as nullable).
	funcsByName := make(map[string][]*db.Function, len(funcs))
	for _, fn := range funcs {
		funcsByName[fn.Name] = append(funcsByName[fn.Name], fn)
	}
	// definedNames distinguishes an in-scan callee (resolve via the fixpoint)
	// from an external one (fail-open). Without it, `return external_func();`
	// would be assumed non-null — the same closed-world bug that hid the
	// global-field getter. Prototypes live in function_declarations and are
	// absent here, so external nullability remains fail-open.
	definedNames := make(map[string]bool, len(funcsByName))
	for name := range funcsByName {
		definedNames[name] = true
	}

	// Batch-load summaries and files once, avoiding per-function point queries.
	allFnIDs := make([]int64, 0, len(funcs))
	for _, fn := range funcs {
		allFnIDs = append(allFnIDs, fn.ID)
	}
	summariesByID, err := f.store.ListSummariesByFunctionIDs(ctx, allFnIDs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ret nullable summary: list summaries: %w", err)
	}
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
		arrs   *arrayBaseInfo
		srcs   []nullSource
	}
	infos := make([]funcInfo, 0, len(needNames))
	seededDefs := make([]funcInfo, 0)
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
			// Return-type gate: on a never-null scalar return type the literal
			// is the integer zero, not a null pointer (a legacy summary row).
			// A gated seed falls through to the ordinary body analysis.
			if sum := summariesByID[fn.ID]; sum != nil && sum.ReturnNullable &&
				!apikb.IsNeverNullScalarType(strings.TrimSpace(fn.ReturnType)) {
				// A literal NULL return in a pointer-returning function is a
				// concrete witness: the seed grade is proven. The body still
				// carries the facts the conditional-nonnull-getter contract
				// needs (where the NULL returns sit, what else is returned),
				// so the definition is recorded for that pass — the fixpoint
				// itself is skipped via the seeded grade.
				retNullable[fn.Name] = retNullProven
				seededDefs = append(seededDefs, funcInfo{fn: fn, body: body, root: root, params: paramsOf(fn, root)})
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
			params := paramsOf(fn, root)
			infos = append(infos, funcInfo{fn: fn, body: body, root: root, params: params, arrs: collectArrayBaseInfo(root, body, params), srcs: srcs})
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
	analyzer.helperParams = collectNullCheckHelpers(cache, funcs, fileByID)
	analyzer.macroGuards = collectMacroGuards(cache, fileByID)

	// defAssumed records, per function definition, whether its nullable
	// evidence is fail-open (assumed) rather than proven. The name-level
	// grade then merges conservatively: any assumed definition downgrades the
	// whole name, because a same-name call site cannot be resolved to one
	// definition and an assumption must never reach the auto-confirm channel.
	defAssumed := make(map[int64]bool)
	firstRound := true
	for {
		changed := false
		for i := range infos {
			info := &infos[i]
			// First round computes every definition unconditionally so each
			// one records its assumed/proven grade; later rounds keep the
			// original skip (the name is already nullable, no new bool fact).
			if !firstRound && retNullable[info.fn.Name] != retNotNull {
				continue
			}
			srcs := append([]nullSource(nil), info.srcs...)
			srcs = append(srcs, callResultNullSources(info.body, retNullable)...)
			flow := analyzer.analyzeFlow(ctx, info.fn, info.body, info.root, nullGenByLine(srcs), nil, true, false)
			if ns := returnsNullability(info.body, flow, info.params, retNullable, definedNames, info.arrs, srcs, strings.TrimSpace(info.fn.ReturnType)); ns != retNotNull {
				retNullable[info.fn.Name] = ns
				defAssumed[info.fn.ID] = ns == retNullAssumed
				changed = true
			}
		}
		firstRound = false
		if !changed {
			break
		}
	}
	// Collapse the boolean fixpoint result into the graded map: a nullable
	// name is proven only when NONE of its definitions carries assumed-only
	// evidence.
	retGrade := make(map[string]retNullability, len(retNullable))
	for name := range retNullable {
		grade := retNullProven
		for _, fn := range funcsByName[name] {
			if defAssumed[fn.ID] {
				grade = retNullAssumed
				break
			}
		}
		retGrade[name] = grade
	}

	// Inter-procedural NULL-return guard contracts: names proven nullable
	// whose every definition returns NULL only under a parameter null check
	// (R2 getter) or a parameter null check / strlen overflow check (R3
	// strip-style helper), with otherwise non-null returns (address-of or
	// parameter forwarding). A name qualifies only when ALL of its
	// definitions qualify consistently (a same-name call site cannot resolve
	// to one definition, so one non-qualifying or divergent definition must
	// keep the name off the list). Seeded definitions (a literal NULL return
	// with a function_summary row) skipped the fixpoint body pass, so they
	// are merged back here.
	infoByID := make(map[int64]*funcInfo, len(infos)+len(seededDefs))
	for i := range infos {
		infoByID[infos[i].fn.ID] = &infos[i]
	}
	for i := range seededDefs {
		if infoByID[seededDefs[i].fn.ID] == nil {
			infoByID[seededDefs[i].fn.ID] = &seededDefs[i]
		}
	}
	retGuards := make(map[string]*retNullGuard)
	for name, grade := range retGrade {
		if grade != retNullProven {
			continue
		}
		allOK, seen := true, false
		var merged *retNullGuard
		for _, fn := range funcsByName[name] {
			info := infoByID[fn.ID]
			if info == nil {
				allOK = false
				break
			}
			g := retNullGuardContract(info.body, info.params)
			if g == nil {
				allOK = false
				break
			}
			if merged != nil && (merged.paramNullOnly != g.paramNullOnly || merged.overflowArg != g.overflowArg || merged.overflowLen != g.overflowLen) {
				allOK = false
				break
			}
			merged = g
			seen = true
		}
		if seen && allOK {
			retGuards[name] = merged
		}
	}
	return retGrade, definedNames, retGuards, nil
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

// callerNullDetail returns a human-readable origin for a parameter whose
// nullability comes from a caller (origin "caller_null"), or "" for a
// non-parameter source.
func callerNullDetail(m *nullModel, variable string) string {
	if m == nil {
		return ""
	}
	for _, s := range m.sources {
		if s.variable != variable || s.origin != "caller_null" {
			continue
		}
		if s.chainOpen {
			// The open-chain fixpoint graded this parameter OPEN: a possibly-
			// null value can actually reach it (a literal-NULL call site, or a
			// forwarding chain rooted at an unguarded external entry).
			if s.argText == "NULL" || s.argText == "0" {
				return fmt.Sprintf("caller %s passes NULL", s.caller)
			}
			if s.caller == "" {
				return "the value flows from an unguarded external entry (no in-tree call site guards this parameter)"
			}
			return fmt.Sprintf("caller %s forwards %s from an unguarded entry chain", s.caller, s.argText)
		}
		if s.argText == "NULL" || s.argText == "0" {
			return fmt.Sprintf("caller %s passes NULL", s.caller)
		}
		return fmt.Sprintf("caller %s passes %s (not proven non-null)", s.caller, s.argText)
	}
	return ""
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
