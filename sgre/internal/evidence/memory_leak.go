package evidence

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type MemoryLeakDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewMemoryLeakDetector(store db.Store, p *parser.Parser, logger *log.Logger) *MemoryLeakDetector {
	return &MemoryLeakDetector{store: store, parser: p, logger: logger}
}

func (d *MemoryLeakDetector) Name() string { return "memory_leak" }

func (d *MemoryLeakDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Wrapper functions that return an allocator result (the "封装成函数"
	// production pattern) are allocation sites even with a custom name. Computed
	// once for the whole codebase, not per file.
	allocReturns, borrowFuncs, escapeFuncs, err := allocatorReturnFuncs(ctx, d.store, d.parser, d.logger)
	if err != nil {
		return result, err
	}
	// Bump/arena allocators (`pool_alloc` → `g_pool + g_off`) hand back interior
	// pointers into a pool released wholesale by its owner, so an individual
	// result is never a per-object leak (issue #206 A.3).
	bumpAllocators, err := bumpAllocatorFuncs(ctx, d.store, d.parser, d.logger)
	if err != nil {
		return result, err
	}
	// Cross-file typedef resolution: a `typedef int Status; Status st = ...` must
	// count as a scalar status code, not an allocation (EL-06).
	globalTypedefs := buildGlobalTypedefs(ctx, d.store, d.parser)

	// Release-helper summaries (issue #281 M1): a business-named helper
	// (`table_teardown(t)`) whose body does `free(t)` releases the argument even
	// though its name carries no free/destroy/delete/cleanup/recycle spelling.
	// The summaries are the tree-wide ParamDirectFrees facts the other
	// detectors (UAF / double-free / container-field-leak) already consume;
	// memory_leak now reads them too instead of relying on the name heuristic.
	summaries, err := buildFuncSummaries(ctx, d.store, d.parser, d.logger)
	if err != nil {
		return result, err
	}

	// Global-container shallow-free analysis (issue #255): the deletion path
	// releases an object owned by a global container but not the object's
	// heap-owning fields. It runs before the allocation-centric loop because it
	// also emits the ownership-transfer releases that re-home an allocation
	// stored into a wrapper object.
	if err := d.detectGlobalContainerFieldLeaks(ctx, globalTypedefs, allocReturns, &result); err != nil {
		return result, err
	}

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, fileFuncs []*db.Function, tree *parser.Tree) {
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		decls := root.FindAll("declaration")
		ifs := root.FindAll("if_statement")
		ids := root.FindAll("identifier")
		macros := macroFreeSummaries(root)
		typedefs := globalTypedefs.clone()
		typedefs.addRoot(root)

		for _, f := range fileFuncs {
			localVars := findLocalVarsFrom(decls, f)
			scalarVars := findScalarVarsFrom(decls, f, typedefs)
			allocs := d.findAllocations(ctx, f, file, assigns, inits, calls, allocReturns, borrowFuncs, scalarVars, bumpAllocators)
			frees := d.findFrees(ctx, f, file, calls, macros, inits, assigns, summaries)
			returnLines := findReturnLinesFrom(returns, f)

			body := bodies[f.StartLine]
			cfg, lease := buildStmtCFGFromCtx(ctx, f, body, tree)
			if lease != nil {
				defer lease.Release()
			}
			cfgValid := body.Kind() == "compound_statement"
			// The set of variables this function allocates. A pointer stored
			// through one of them (`*container = buf`) points INTO the heap, not
			// the stack, so its content escapes with the container's ownership
			// rather than leaking on its own (see findEscapeLines' pointer case).
			allocVarNames := make(map[string]bool, len(allocs))
			for name := range allocs {
				allocVarNames[name] = true
			}

			for varName, allocSites := range allocs {
				// realloc into a DIFFERENT target (`tmp = realloc(p, n)`) consumes
				// p's block on success and leaves p reachable on failure, so p is
				// never leaked by that call — model it as a release at the realloc
				// line so p is not reported.
				reallocConsumeLines := findReallocConsumeLines(assigns, inits, f, varName)
				// self-realloc `p = realloc(p, n)` leaks the OLD block when realloc
				// fails (returns NULL) — ML-12.
				selfReallocLines := findSelfReallocLines(assigns, inits, f, varName)
				// Lines where a `return varName` hands the pointer to the caller.
				// A return on ONE path is an ownership transfer on that path only;
				// the path-sensitive analysis below treats it as a leak-avoiding
				// node rather than (the old, coarse) a function-wide transfer flag,
				// so `if (err) return p; ...` no longer suppresses a leak on the
				// non-returning path.
				transferLines := findReturnVarLines(varName, returns, f)
				filteredReturns := filterNullGuardReturns(ifs, returnLines, varName)
				nullGuardReturns := subtractLines(returnLines, filteredReturns)
				// Early returns guarded by a FAILED output-param allocator check
				// (`if (asprintf(&p, ...) < 0) return;`) are not leak evidence for
				// the out-param variable: the allocation never happened on that
				// branch (docs §5.3 success-branch binding).
				nullGuardReturns = append(nullGuardReturns, findAllocGuardedReturns(ifs, returns, assigns, inits, f, varName)...)
				escapeLinesAll := findEscapeLines(assigns, calls, returns, ids, f, varName, localVars, allocVarNames, allocReturns, true, escapeFuncs)
				overwriteLines := writeLinesFor(assigns, inits, f, varName)

				for _, site := range allocSites {
					allocLine := site.line
					allocAPI := callNameAtLine(calls, allocLine)
					// A release of the exact field (free(s.a)) releases only that
					// field's allocation; a whole-struct/whole-variable release
					// (cleanup(&s), free(p)) is recorded under the base and releases
					// every field allocation under it (Issue #288).
					allFreeCalls := append([]freeCall(nil), frees[site.key]...)
					if base := allocKeyBase(site.key); base != site.key {
						allFreeCalls = append(allFreeCalls, frees[base]...)
					}
					for _, l := range reallocConsumeLines {
						allFreeCalls = append(allFreeCalls, freeCall{line: l, api: "realloc"})
					}
					// Family pairing (docs §6): an object allocated by a modeled
					// API is validly released only by its ValidFrees (plus generic
					// releases where the model allows). A mismatched releaser —
					// xmlXPathFreeContext on an XPath object, free() on an XPath
					// context, cJSON_Delete on strdup's block — does NOT count as a
					// release; the allocation leaks and the mismatch is surfaced in
					// the event props for the AI.
					effectiveCalls, hasFree, mismatchedCalls := effectiveFreeCalls(allFreeCalls, allocAPI)
					freeLines := freeCallLines(effectiveCalls)
					// Conditional ownership transfer (docs §5.2C): a modeled
					// TransferOnSuccess call guarded by its own return value with
					// no failure-branch release is NOT an unconditional escape —
					// the failure path still owns (and leaks) the object.
					escapeLines, conditionalTransfers := splitConditionalEscapes(escapeLinesAll, calls, ifs, freeLines)
					shouldReportLeak := false
					shouldReportRelease := false

					if isGuardedRelease(ifs, varName, freeLines) {
						// Released only inside a positive guard (`if (p) { free(p); }`):
						// the NULL path carries no allocation, so skipping the free on
						// that branch is not a leak. Mirrors resource-leak's guarded-
						// release branch (isGuardedRelease is shared across detectors).
						shouldReportRelease = true
					} else if cfgValid {
						if hasLostResource(cfg, allocLine, freeLines, nullGuardReturns, escapeLines, transferLines, overwriteLines) {
							shouldReportLeak = true
						} else {
							shouldReportRelease = true
						}
					} else if !hasFree {
						// No CFG to prove a leak path: fall back to the coarse
						// heuristic. A malloc whose result escapes at its site or is
						// returned anywhere is ownership-transferred, not leaked.
						if containsLine(escapeLines, allocLine) || len(transferLines) > 0 {
							shouldReportRelease = true
						} else {
							shouldReportLeak = true
						}
					} else {
						shouldReportRelease = true
					}

					// ML-12: a self-realloc p = realloc(p, n) immediately consuming
					// this allocation leaks the OLD block when realloc fails (returns
					// NULL), even if a later free(p) releases the NEW block. Force a
					// suspected leak instead of a release.
					for _, rl := range selfReallocLines {
						if rl <= allocLine {
							continue
						}
						immediate := true
						for _, fl := range freeLines {
							if fl > allocLine && fl < rl {
								immediate = false
								break
							}
						}
						if immediate {
							shouldReportLeak = true
							shouldReportRelease = false
							break
						}
					}

					if shouldReportLeak {
						// ML-01/18: a pointer with NO free/transfer/escape on any path is
						// DEFINITELY lost (hasLostResource proved a leak path AND there is
						// no releasing/handing-off node anywhere), so mark it so the
						// planner can confirm instead of leaving it suspected.
						// Extended: even when free/escape/transfer lines exist, if none
						// is structurally reachable from the allocation in the CFG (dead
						// code after an unconditional return/goto), the leak is still
						// definite — the release can never execute. A conditional
						// transfer is a channel that exists (the success branch hands
						// the object off), so it keeps the guarded-failure leak
						// suspected for the AI rather than definite.
						definiteLeak := len(freeLines) == 0 && len(escapeLines) == 0 && len(conditionalTransfers) == 0 && len(transferLines) == 0
						if !definiteLeak && cfgValid && !canReachAnyRelease(cfg, allocLine, freeLines, append(append([]int{}, escapeLines...), conditionalTransfers...), transferLines) {
							definiteLeak = true
						}
						props := map[string]string{
							"variable":    varName,
							"origin":      "malloc",
							"api":         allocAPI,
							"escape_kind": leakEscapeKind(escapeLines, transferLines),
						}
						if len(freeLines) > 0 {
							props["free_lines"] = joinIntLines(freeLines)
						}
						if len(conditionalTransfers) > 0 {
							props["transfer_conditional"] = joinCallLines(calls, conditionalTransfers)
						}
						if len(mismatchedCalls) > 0 {
							props["free_mismatch"] = joinFreeCalls(mismatchedCalls)
						}
						if definiteLeak {
							props["definite"] = "true"
						}
						if emitEvent(ctx, d.store, d.logger, "MEMORY_ALLOC", f.ID, &db.Location{FileID: file.ID, Line: allocLine}, props) {
							result.EventsCreated++
						}
					}

					if shouldReportRelease {
						if emitEvent(ctx, d.store, d.logger, "MEMORY_ALLOC", f.ID, &db.Location{FileID: file.ID, Line: allocLine}, map[string]string{
							"variable": varName,
							"origin":   "malloc",
							"api":      allocAPI,
						}) {
							result.EventsCreated++
						}
						releaseLine := allocLine
						freeAPI := allocAPI
						if len(effectiveCalls) > 0 {
							releaseLine = effectiveCalls[0].line
							freeAPI = effectiveCalls[0].api
						}
						// alloc_line ties this release to its specific allocation
						// site, so the planner's ReleaseFilter drops only the released
						// site and not a sibling alloc site that leaks.
						if emitEvent(ctx, d.store, d.logger, "MEMORY_RELEASE", f.ID, &db.Location{FileID: file.ID, Line: releaseLine}, map[string]any{
							"variable":   varName,
							"origin":     "free",
							"alloc_line": allocLine,
							"free_api":   freeAPI,
						}) {
							result.EventsCreated++
						}
					}

				}
			}
			// Free-on-borrow: a deallocator call on a variable whose value
			// came from a borrowed-return API (cJSON_GetObjectItem, strstr,
			// getenv, ...) releases an object the caller does not own — an
			// invalid free with use-after-free / double-free / heap-corruption
			// consequences when the real owner releases it later
			// (cJSON_Delete(root) walking a child list whose item was already
			// deleted). Surfaced as a suspected candidate (never
			// auto-confirmed: the memory-leak type carries it, the classifier
			// judges the CWE-415/416 consequence).
			for _, site := range findFreeOnBorrowSites(assigns, inits, calls, f) {
				props := map[string]string{
					"variable":    site.variable,
					"origin":      "free-borrow",
					"api":         site.borrowAPI,
					"borrow_free": site.freeAPI,
				}
				if emitEvent(ctx, d.store, d.logger, "MEMORY_ALLOC", f.ID, &db.Location{FileID: file.ID, Line: site.line}, props) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}
