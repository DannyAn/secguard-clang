package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// null_flow.go implements a flow-sensitive "may be null" analysis for the
// null-deref pipeline. It replaces the previous line-order heuristic (a
// NULL_VALUE source at or before the dereference line) with a real dataflow
// over the statement-level control-flow graph (CFG), so the graph layer that
// sgre already builds is finally consumed by the convergence pipeline:
//
//   - CFG (control_flow.go): a null source only counts if a control-flow path
//     from the source reaches the dereference. A `return`/`break` before the
//     deref, or a source confined to a mutually-exclusive branch, no longer
//     reaches it.
//   - DATA_FLOW edges (graph_edges): value flow between variables (`v = w`)
//     propagates nullness from w to v, so a null source on w reaches a later
//     dereference of v.
//   - definite non-null kills: an assignment from an address-of (`v = &x`), a
//     string literal (`v = ""`), or an array (`v = arr`) provably clears
//     nullness, so a stale NULL_VALUE source no longer produces a candidate.
//
// The analysis is a forward *may* analysis (union over paths), so it is
// conservative in the direction that matters: it can only prove a variable is
// NOT null on every path, never falsely clear a null that could reach the
// dereference. When the parser or source file is unavailable the caller falls
// back to the old line-order heuristic, preserving the offline/mock behavior.
// copyPair is one intra-procedural value flow: at line, lhs receives rhs's
// value (`lhs = rhs`).
type copyPair struct {
	lhs string
	rhs string
}

// flowAnalyzer builds and caches the flow analysis inputs shared across a
// filter application: the DATA_FLOW edge copy map and parsed file trees.
type flowAnalyzer struct {
	store  db.Store
	parser *parser.Parser
	// cfgCache memoizes per-function *graph.StmtCFG across analyzeFlow /
	// analyzeFlowMust and across the filters that share this analyzer's
	// callsite. nil falls back to uncached BuildStmtCFG.
	cfgCache *graph.CFGCache
	// tree is the ParseCached borrow for the body currently being analyzed.
	// When set (with cfgCache), analyzeFlow/analyzeFlowMust lease the CFG with
	// this tree so the shared cache can reuse it across filters safely.
	tree *parser.Tree

	// dfgEdges caches all DATA_FLOW edges, resolved to (function, lhs, rhs, line)
	// copies, keyed by function ID then line.
	dfgCopies map[int64]map[int][]copyPair
	// entrySeeds are variables tainted at function entry (caller-influenced
	// parameters). They are seeded into IN[entry] so a parameter's taint flows
	// into locals derived from it — the inter-procedural context of the callee.
	entrySeeds map[string]bool
	// definiteEntrySeeds are parameters PROVEN null by a caller (a caller passes
	// a literal NULL). They seed the must-null tier so such a dereference is
	// confirmed, not merely suspected.
	definiteEntrySeeds map[string]bool
	// helperParams is the cross-file null-check predicate-helper summary, and
	// macroGuards the cross-file guard-macro summary; both feed the guard model.
	helperParams map[string][]int
	macroGuards  map[string]macros.GuardSummary
	// macroWrites is the whole-tree merged macro write-summary cache. When set,
	// it replaces the per-file WriteSummaries in macroWritesFor so a macro
	// defined in a .h header (SAMPLE_Scan, POOL_FOR, ...) is visible at call
	// sites in every .c source. nil falls back to per-file analysis.
	macroWrites map[string]macros.WriteSummary
	// iterMacros is the merged iterator-macro lookup (built-in apikb table +
	// config-declared project macros) whose iterator parameter(s) are written
	// in the for-init and null-guarded by the loop condition. nil falls back to
	// apikb.IteratorArgs alone.
	iterMacros map[string][]int
	// scopeNames caches, per function body (keyed by start byte), the scope
	// oracle for the `(A) & x` disambiguation. The planner analyzes each
	// function once per filter application, and a nil oracle falls back to the
	// permissive recognition.
	scopeNames map[int]func(string) bool
	// constants caches the file-level ConstantEnv (macro/enum zero symbols) by
	// file ID so buildGuardCtx does not re-walk the whole file per function.
	constants map[int64]*parser.ConstantEnv
}

// scopeOracle returns the `(A) & x` disambiguation oracle for a function body:
// the names bound to values in that function (see parser.FunctionBoundNames).
// Without it a genuine bit-and argument (`f((flags) & p)`) would be read as an
// address-of and would kill p's null state, hiding the dereference.
func (a *flowAnalyzer) scopeOracle(body parser.Node) func(string) bool {
	if a.scopeNames == nil {
		a.scopeNames = make(map[int]func(string) bool)
	}
	key := body.StartByte()
	if o, ok := a.scopeNames[key]; ok {
		return o
	}
	bound := parser.FunctionBoundNamesByBody(body)
	var o func(string) bool
	if bound != nil {
		o = func(name string) bool { return bound[name] }
	}
	a.scopeNames[key] = o
	return o
}

func newFlowAnalyzer(store db.Store, p *parser.Parser, cfgCache *graph.CFGCache) *flowAnalyzer {
	return &flowAnalyzer{store: store, parser: p, cfgCache: cfgCache}
}

// flowResult is the per-function dataflow result.
type flowResult struct {
	cfg   *graph.StmtCFG
	lease *graph.CFGLease
	// spans/startLines are a compact geometry snapshot of cfg. The CFG itself
	// (and its parser.Nodes) is released as soon as the analysis is built, so a
	// flowResult can be cached across filters without pinning the AST.
	// NodeAt/NodeAtColumn are reimplemented over these spans below.
	spans      []flowSpan
	startLines []int
	// nodeIn maps node ID -> variable -> set of source node IDs that may reach
	// this node. This is a reaching-definitions lattice (not a plain boolean)
	// so that a kill (a definite non-null reassignment, a release, ...) clears
	// a variable's sources without the anti-monotonicity bug a boolean lattice
	// would introduce.
	nodeIn map[int]map[string]map[int]bool
	// genAt records which variables gain a source at each node, so a source on
	// the same statement as the queried point still counts.
	genAt map[int]map[string]bool
	// selfReadGenAt marks, per node, the variables whose source at that node is
	// a SELF-referential field-read update (`node = node->next`, origin
	// "field_read"). Such a statement reads the pointer's OLD value on its
	// right side and only then overwrites it, so the new source cannot reach a
	// dereference inside that same statement — it reaches only the statements
	// after it (the post-advance use the loop condition no longer guards, which
	// is the real defect this source exists to model). Without the exclusion,
	// every `while (node) { ...; node = node->next; }` walk reported its own
	// guard-protected update as a null-deref.
	selfReadGenAt map[int]map[string]bool
	// must is a boolean must-analysis (the fact holds on EVERY path) over the
	// same effects as nodeIn. It is computed on demand for the freed-state and
	// uninit filters, where a "confirmed" upgrade requires the fact to reach the
	// use on all paths, not merely on one.
	must map[int]map[string]bool
	// mustGenAt records which variables gain the fact at each node (the must
	// analogue of genAt).
	mustGenAt map[int]map[string]bool
	// definite is a boolean must-analysis seeded ONLY with explicit null
	// assignments (`p = NULL`), with any non-copy reassignment killing it. A
	// reaching fact means the pointer is CERTAINLY null — a must-null result,
	// distinct from the may-null `reaching`.
	definite map[int]map[string]bool
	// definiteGenAt records the explicit-null gen at each node.
	definiteGenAt map[int]map[string]bool
	// weakGuard marks variables that are both null-checked and dereferenced in
	// the same control-flow condition (`p == NULL || p->field`), where the
	// dereference is short-circuit-protected and therefore not a null-deref.
	weakGuard map[int]map[string]bool
	// ternaryGuard records the guarded branches of conditional expressions
	// (`p != NULL ? p->field : d` guards p inside the consequence; `p == NULL ?
	// d : p->field` guards p inside the alternative). A conditional expression
	// stays inside one straight-line CFG node, so these guards cannot ride the
	// edge-kill model; they are resolved by line range at the nullable-source
	// convergence stage.
	ternaryGuard []ternaryGuardEntry
	// contract holds the alias / void*-contract provenance facts for the
	// function, used by the nullable-source filter to converge derived variables
	// that the event-keyed null model cannot resolve (see null_contract.go).
	contract *contractCtx
}

// nodeAt resolves a source position to its CFG statement node, using the column
// when it is known so several statements on ONE line (a `for` header's
// initializer / condition / update) are not conflated.
func (m *flowResult) nodeAt(line, column int) *graph.StmtNode {
	if m == nil {
		return nil
	}
	return nodeAtSpans(m.spans, line, column)
}

// nodeAtSpans resolves a source position over geometry snapshots. It mirrors
// graph.StmtCFG.NodeAt/NodeAtColumn without touching parser.Nodes.
func nodeAtSpans(spans []flowSpan, line, column int) *graph.StmtNode {
	if len(spans) == 0 {
		return nil
	}
	best := -1
	for i := range spans {
		sp := &spans[i]
		if line < sp.start || line > sp.end {
			continue
		}
		if column > 0 && (sp.column <= 0 || sp.column > column) {
			continue
		}
		if best < 0 {
			best = i
			continue
		}
		b := &spans[best]
		br, nr := b.end-b.start, sp.end-sp.start
		if column > 0 {
			if nr < br || (nr == br && sp.column > b.column) {
				best = i
			} else if nr == br && sp.column == b.column && b.control && !sp.control {
				best = i
			}
		} else if nr < br || (nr == br && b.control && !sp.control) {
			best = i
		}
	}
	if best < 0 {
		if column > 0 {
			return nodeAtSpans(spans, line, 0)
		}
		return nil
	}
	sp := &spans[best]
	return &graph.StmtNode{ID: sp.id, StartLine: sp.start, EndLine: sp.end, StartColumn: sp.column, IsControl: sp.control}
}

// reaching reports whether variable has a reaching source at line.
func (m *flowResult) reaching(variable string, line int) bool {
	return m.reachingAt(variable, line, 0)
}

// reachingAt is reaching with the sink's COLUMN, which disambiguates statements
// that share a line (see graph.StmtCFG.NodeAtColumn).
func (m *flowResult) reachingAt(variable string, line, column int) bool {
	n := m.nodeAt(line, column)
	if n == nil {
		return false
	}
	if len(m.nodeIn[n.ID][variable]) > 0 {
		return true
	}
	if m.selfReadGenAt[n.ID][variable] {
		return false
	}
	return m.genAt[n.ID][variable]
}

// reachingDefinite reports whether an EXPLICIT null assignment (`p = NULL`)
// reaches the dereference on EVERY path with no intervening kill — i.e. the
// pointer is certainly null. This is the must-null tier the AI does not need to
// re-derive.
func (m *flowResult) reachingDefinite(variable string, line int) bool {
	return m.reachingDefiniteAt(variable, line, 0)
}

// reachingDefiniteAt is reachingDefinite with the sink's COLUMN (see
// graph.StmtCFG.NodeAtColumn). Without it, `p = NULL;` followed by
// `for (p = &x; p != NULL; p = p->next)` resolved the update's `p->next`
// dereference to the INITIALIZER node, whose incoming definite-null fact is
// "p is NULL" — an auto-confirmed false positive on the commonest C list walk.
func (m *flowResult) reachingDefiniteAt(variable string, line, column int) bool {
	if m == nil || m.definite == nil {
		return false
	}
	n := m.nodeAt(line, column)
	if n == nil {
		return false
	}
	if m.definite[n.ID][variable] {
		return true
	}
	return m.definiteGenAt[n.ID][variable]
}

func (m *flowResult) weakGuardAt(variable string, line int) bool {
	if m == nil || m.weakGuard == nil {
		return false
	}
	n := m.nodeAt(line, 0)
	return n != nil && m.weakGuard[n.ID][variable]
}

// ternaryGuardAt reports whether the dereference of variable at line sits
// inside a guarded branch of a conditional expression (`p != NULL ? p->f : d`).
func (m *flowResult) ternaryGuardAt(variable string, line int) bool {
	if m == nil || len(m.ternaryGuard) == 0 {
		return false
	}
	for _, g := range m.ternaryGuard {
		if g.variable == variable && g.line == line {
			return true
		}
	}
	return false
}

// loopBoundGuardAt reports whether (variable, line) is a subscript dereference
// guarded by a loop bound (`for (i < n) arr[i]` with arr = f(&n)).
func loopBoundGuardAt(entries []ternaryGuardEntry, variable string, line int) bool {
	for _, g := range entries {
		if g.variable == variable && g.line == line {
			return true
		}
	}
	return false
}

// mustReachingAt is mustReaching with the sink's COLUMN (see
// graph.StmtCFG.NodeAtColumn): two statements sharing ONE line (a failure
// return and a cleanup free) resolve to different CFG nodes, so the must-flow
// verdict no longer rests on a line-level ambiguity (issue #253 P2-1).
//
// It deliberately does NOT count a gen that sits ON the sink node itself: the
// fact must hold BEFORE the sink. A use-after-free sink is the use (the free is
// an earlier node) and a double-free sink is the SECOND free (the first free is
// an earlier node), so the sink's own gen is the event being judged, not a
// premise. Counting it made a conditional free look unconditional whenever the
// free and the sink shared a line (`if (c) { free(p); } p->v = 1;` or
// `if (c) { free(p); } free(p);`), because collectNodeEffects applies the
// line-keyed gen to every non-control node on that line. A genuine
// unconditional free still reaches the sink through the in-state, so the
// confirmed tier keeps its proof.
func (m *flowResult) mustReachingAt(variable string, line, column int) bool {
	if m == nil || m.must == nil {
		return false
	}
	n := m.nodeAt(line, column)
	if n == nil {
		return false
	}
	return m.must[n.ID][variable]
}

// sourceLine returns the line of the first reaching source for variable at
// line, or 0 if none. It picks the minimum source line so the codeFlow step
// is deterministic across runs.
func (m *flowResult) sourceLine(variable string, line int) int {
	return m.sourceLineAt(variable, line, 0)
}

// sourceLineAt is sourceLine with the sink's COLUMN (see
// graph.StmtCFG.NodeAtColumn).
func (m *flowResult) sourceLineAt(variable string, line, column int) int {
	n := m.nodeAt(line, column)
	if n == nil {
		return 0
	}
	srcs := m.nodeIn[n.ID][variable]
	if len(srcs) == 0 {
		if m.genAt[n.ID][variable] && !m.selfReadGenAt[n.ID][variable] {
			return n.StartLine
		}
		return 0
	}
	best := 0
	for sid := range srcs {
		if sid < 0 || sid >= len(m.startLines) {
			continue
		}
		sl := m.startLines[sid]
		if sl > 0 && (best == 0 || sl < best) {
			best = sl
		}
	}
	return best
}

// nodeEffects are the gen/kill/copy transfer effects of a single CFG node.
type nodeEffects struct {
	gen  map[string]bool
	kill map[string]bool
	copy map[string]string
	// copyFieldBase records, for a field/subscript-read copy (`q = p->f`,
	// `q = p[i]`, `q = (T*)p->f`), the base pointer `p` whose null sources ALSO
	// propagate to q. Reading a field of a possibly-null base yields a value of
	// unknown nullness (the read is UB if p is null; the field value is
	// independently nullable otherwise), so q inherits p's may-null fact in
	// addition to the field location p->f's own. Null-deref only (populated when
	// nonNullKills is set), so taint / freed-state / uninit flows are unchanged.
	copyFieldBase map[string]string
	// killBase records whole-variable reassignments (`p = ...`). Because the key
	// "p->f" is the field f of whatever object p CURRENTLY points to, reassigning
	// p to a different object invalidates every p->f / p[i] fact.
	killBase map[string]bool
}

// analyzeFunction builds and runs the null-source flow analysis for one
// function, given its parsed body and the NULL_VALUE sources observed in it.
func (a *flowAnalyzer) analyzeFunction(ctx context.Context, fn *db.Function, body parser.Node, fileRoot parser.Node, sources []nullSource) *flowResult {
	genByLine := make(map[int][]string)
	definiteGenByLine := make(map[int][]string)
	for _, s := range sources {
		genByLine[s.line] = append(genByLine[s.line], s.variable)
		if s.definite {
			definiteGenByLine[s.line] = append(definiteGenByLine[s.line], s.variable)
		}
	}
	res := a.analyzeFlow(ctx, fn, body, fileRoot, genByLine, nil, true, false)
	if res != nil {
		// A self-referential field-read update (`node = node->next`) generates a
		// may-null source for the SAME variable on the line it also dereferences
		// that variable. The assignment's right-hand side reads the old value,
		// so the new source only flows forward — exclude it from the
		// same-statement sink (see flowResult.selfReadGenAt).
		for _, s := range sources {
			if s.origin != "field_read" || s.line <= 0 {
				continue
			}
			n := res.nodeAt(s.line, s.column)
			if n == nil {
				continue
			}
			if res.selfReadGenAt == nil {
				res.selfReadGenAt = make(map[int]map[string]bool, len(sources))
			}
			if res.selfReadGenAt[n.ID] == nil {
				res.selfReadGenAt[n.ID] = map[string]bool{}
			}
			res.selfReadGenAt[n.ID][s.variable] = true
		}
	}
	return res
}

type flowSpan struct {
	id      int
	start   int
	end     int
	column  int
	control bool
}

// snapshotFlow replaces the live cfg dependency with geometry-only spans so the
// CFG lease can be released immediately.
func (r *flowResult) snapshotFlow(cfg *graph.StmtCFG) {
	if r == nil {
		return
	}
	r.spans, r.startLines = snapshotSpans(cfg)
}

func snapshotSpans(cfg *graph.StmtCFG) ([]flowSpan, []int) {
	if cfg == nil {
		return nil, nil
	}
	spans := make([]flowSpan, 0, len(cfg.Nodes))
	startLines := make([]int, len(cfg.Nodes))
	for i, n := range cfg.Nodes {
		startLines[i] = n.StartLine
		if n.Kind == "stmt" {
			spans = append(spans, flowSpan{id: n.ID, start: n.StartLine, end: n.EndLine, column: n.StartColumn, control: n.IsControl})
		}
	}
	return spans, startLines
}

// acquireCFG leases the shared CFG when the analyzer has an AST borrow,
// otherwise builds directly. The lease is carried by flowResult and released
// by the consuming filter when it stops using the flow.
func (a *flowAnalyzer) acquireCFG(ctx context.Context, fn *db.Function, body parser.Node) (*graph.StmtCFG, *graph.CFGLease) {
	return acquirePlannerCFG(ctx, a.cfgCache, a.tree, fn, body)
}

func acquirePlannerCFG(ctx context.Context, cache *graph.CFGCache, tree *parser.Tree, fn *db.Function, body parser.Node) (*graph.StmtCFG, *graph.CFGLease) {
	if cache != nil && tree != nil && fn != nil && fn.ID > 0 {
		lease := cache.Acquire(ctx, fn.ID, tree, func() *graph.StmtCFG {
			return graph.BuildStmtCFG(body, fn.EndLine)
		})
		return lease.CFG(), lease
	}
	return graph.BuildStmtCFG(body, fn.EndLine), nil
}

// release drops the CFG lease held by the flow (if any).
func (r *flowResult) release() {
	if r != nil && r.lease != nil {
		r.lease.Release()
		r.lease = nil
	}
}

func releaseFlowResults(flows map[int64]*flowResult) {
	for _, f := range flows {
		f.release()
	}
}

// analyzeFlow builds and runs the reaching-sources dataflow for one function.
// genByLine / killByLine map statement lines to variables that gain / lose a
// source there (a kill clears all of the variable's sources). nonNullKills
// additionally treats AST-level definite non-null reassignments (&x, "", arr)
// as kills; it is enabled only for null-deref.
func (a *flowAnalyzer) analyzeFlow(ctx context.Context, fn *db.Function, body parser.Node, fileRoot parser.Node, genByLine, killByLine map[int][]string, nonNullKills, definiteKills bool) *flowResult {
	if body.Kind() != "compound_statement" {
		return nil
	}

	cfg, lease := a.acquireCFG(ctx, fn, body)
	if cfg == nil {
		return nil
	}
	effects := a.buildEffects(cfg, genByLine, killByLine, a.dfgCopies[fn.ID], nonNullKills, definiteKills, a.macroWritesFor(fileRoot, nonNullKills), a.scopeOracle(body))
	// Null guards are path-sensitive kills; they apply only to the null-deref
	// may-analysis (nonNullKills), never to taint/freed-state/uninit flows.
	var guard *guardModel
	if nonNullKills {
		guard = buildGuardModel(cfg, a.helperParams, a.macroGuards, buildGuardCtx(body, a.constantEnvFor(fn, fileRoot)))
	}
	nodeIn := runDataflow(cfg, effects, a.entrySeeds, guard)
	res := &flowResult{cfg: cfg, lease: lease, nodeIn: nodeIn, genAt: genAt(cfg, effects), weakGuard: buildWeakGuardMap(cfg), ternaryGuard: buildTernaryGuardMap(body)}
	res.snapshotFlow(cfg)
	if nonNullKills {
		res.definite, res.definiteGenAt = a.analyzeDefiniteNull(cfg, fileRoot, a.scopeOracle(body), a.definiteEntrySeeds)
	}
	if res.lease != nil {
		res.lease.Release()
		res.lease = nil
	}
	res.cfg = nil
	return res
}

// analyzeFlowMust runs the may reaching-sources dataflow and, over the SAME
// effects, the boolean must dataflow. It is used by the freed-state / uninit
// filters, which need both: may to keep candidates, must to promote a kept
// candidate to "confirmed" only when the fact reaches the use on every path.
func (a *flowAnalyzer) analyzeFlowMust(ctx context.Context, fn *db.Function, body parser.Node, fileRoot parser.Node, genByLine, killByLine map[int][]string, nonNullKills, definiteKills bool) *flowResult {
	if body.Kind() != "compound_statement" {
		return nil
	}

	cfg, lease := a.acquireCFG(ctx, fn, body)
	if cfg == nil {
		return nil
	}
	effects := a.buildEffects(cfg, genByLine, killByLine, a.dfgCopies[fn.ID], nonNullKills, definiteKills, a.macroWritesFor(fileRoot, nonNullKills), a.scopeOracle(body))
	res := &flowResult{cfg: cfg, lease: lease, nodeIn: runDataflow(cfg, effects, a.entrySeeds, nil), genAt: genAt(cfg, effects)}
	res.must, res.mustGenAt = runMustDataflow(cfg, effects, nil)
	res.snapshotFlow(cfg)
	if res.lease != nil {
		res.lease.Release()
		res.lease = nil
	}
	res.cfg = nil
	return res
}
