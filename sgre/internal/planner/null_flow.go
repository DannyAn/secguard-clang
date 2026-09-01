package planner

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
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
	// dfgEdges caches all DATA_FLOW edges, resolved to (function, lhs, rhs, line)
	// copies, keyed by function ID then line.
	dfgCopies map[int64]map[int][]copyPair
	// entrySeeds are variables tainted at function entry (caller-influenced
	// parameters). They are seeded into IN[entry] so a parameter's taint flows
	// into locals derived from it — the inter-procedural context of the callee.
	entrySeeds map[string]bool
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
}

func newFlowAnalyzer(store db.Store, p *parser.Parser) *flowAnalyzer {
	return &flowAnalyzer{store: store, parser: p}
}

// flowResult is the per-function dataflow result.
type flowResult struct {
	cfg *graph.StmtCFG
	// nodeIn maps node ID -> variable -> set of source node IDs that may reach
	// this node. This is a reaching-definitions lattice (not a plain boolean)
	// so that a kill (a definite non-null reassignment, a release, ...) clears
	// a variable's sources without the anti-monotonicity bug a boolean lattice
	// would introduce.
	nodeIn map[int]map[string]map[int]bool
	// genAt records which variables gain a source at each node, so a source on
	// the same statement as the queried point still counts.
	genAt map[int]map[string]bool
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
}

// reaching reports whether variable has a reaching source at line.
func (m *flowResult) reaching(variable string, line int) bool {
	if m == nil || m.cfg == nil {
		return false
	}
	n := m.cfg.NodeAt(line)
	if n == nil {
		return false
	}
	if len(m.nodeIn[n.ID][variable]) > 0 {
		return true
	}
	return m.genAt[n.ID][variable]
}

// reachingDefinite reports whether an EXPLICIT null assignment (`p = NULL`)
// reaches the dereference on EVERY path with no intervening kill — i.e. the
// pointer is certainly null. This is the must-null tier the AI does not need to
// re-derive.
func (m *flowResult) reachingDefinite(variable string, line int) bool {
	if m == nil || m.definite == nil {
		return false
	}
	n := m.cfg.NodeAt(line)
	if n == nil {
		return false
	}
	if m.definite[n.ID][variable] {
		return true
	}
	return m.definiteGenAt[n.ID][variable]
}

// mustReaching reports whether the fact holds on EVERY path to line (the boolean
// must tier). It is the freed-state / uninit analogue of reachingDefinite: used
// to promote a may-reachable candidate to "confirmed" only when the fact is not
// merely possible but provable on all paths.
func (m *flowResult) mustReaching(variable string, line int) bool {
	if m == nil || m.must == nil {
		return false
	}
	n := m.cfg.NodeAt(line)
	if n == nil {
		return false
	}
	if m.must[n.ID][variable] {
		return true
	}
	return m.mustGenAt[n.ID][variable]
}

// sourceLine returns the line of the first reaching source for variable at
// line, or 0 if none. It picks the minimum source line so the codeFlow step
// is deterministic across runs.
func (m *flowResult) sourceLine(variable string, line int) int {
	if m == nil || m.cfg == nil {
		return 0
	}
	n := m.cfg.NodeAt(line)
	if n == nil {
		return 0
	}
	srcs := m.nodeIn[n.ID][variable]
	if len(srcs) == 0 {
		if m.genAt[n.ID][variable] {
			return n.StartLine
		}
		return 0
	}
	best := 0
	for sid := range srcs {
		if sid < 0 || sid >= len(m.cfg.Nodes) {
			continue
		}
		sl := m.cfg.Nodes[sid].StartLine
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
	if res != nil && len(definiteGenByLine) > 0 {
		res.definite, res.definiteGenAt = a.analyzeDefiniteNull(res.cfg)
	}
	return res
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

	cfg := graph.BuildStmtCFG(body, fn.EndLine)
	effects := a.buildEffects(cfg, genByLine, killByLine, a.dfgCopies[fn.ID], nonNullKills, definiteKills, a.macroWritesFor(fileRoot, nonNullKills))
	nodeIn := runDataflow(cfg, effects, a.entrySeeds)
	return &flowResult{cfg: cfg, nodeIn: nodeIn, genAt: genAt(cfg, effects)}
}

// analyzeFlowMust runs the may reaching-sources dataflow and, over the SAME
// effects, the boolean must dataflow. It is used by the freed-state / uninit
// filters, which need both: may to keep candidates, must to promote a kept
// candidate to "confirmed" only when the fact reaches the use on every path.
func (a *flowAnalyzer) analyzeFlowMust(ctx context.Context, fn *db.Function, body parser.Node, fileRoot parser.Node, genByLine, killByLine map[int][]string, nonNullKills, definiteKills bool) *flowResult {
	if body.Kind() != "compound_statement" {
		return nil
	}

	cfg := graph.BuildStmtCFG(body, fn.EndLine)
	effects := a.buildEffects(cfg, genByLine, killByLine, a.dfgCopies[fn.ID], nonNullKills, definiteKills, a.macroWritesFor(fileRoot, nonNullKills))
	res := &flowResult{cfg: cfg, nodeIn: runDataflow(cfg, effects, a.entrySeeds), genAt: genAt(cfg, effects)}
	res.must, res.mustGenAt = runMustDataflow(cfg, effects)
	return res
}

// analyzeDefiniteNull runs the boolean must-null dataflow for the null definite
// tier. Its effects are derived NODE-PRECISELY from each statement's own
// assignments (not from a line-keyed source map): gen = `p = NULL`, kill = any
// other non-copy reassignment, copy = `p = q`. A line-keyed map would collide
// when a one-line `if (c) p = NULL; else p = &x;` puts both the header and its
// branches on one line, falsely assigning the NULL gen to the `p = &x` branch.
func (a *flowAnalyzer) analyzeDefiniteNull(cfg *graph.StmtCFG) (map[int]map[string]bool, map[int]map[string]bool) {
	effects := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		e := &nodeEffects{gen: map[string]bool{}, kill: map[string]bool{}, copy: map[string]string{}}
		for _, p := range directAssignments(n.Stmt) {
			name := assignTargetName(p.lhs)
			if name == "" {
				continue
			}
			if p.lhs.Kind() == "identifier" {
				if e.killBase == nil {
					e.killBase = map[string]bool{}
				}
				e.killBase[name] = true
			}
			if isNullLiteralExpr(p.rhs.Text()) {
				e.gen[name] = true
			} else if rv := copySourceKey(p.rhs); rv != "" {
				e.copy[name] = rv
			} else {
				e.kill[name] = true
			}
		}
		addOutputParamKills(n.Stmt, e, true, nil, a.iterMacros)
		effects[n.ID] = e
	}
	return runMustDataflow(cfg, effects)
}

// buildEffects computes the per-statement-node transfer effects for a CFG.
func (a *flowAnalyzer) buildEffects(cfg *graph.StmtCFG, genByLine, killByLine map[int][]string, dfgByLine map[int][]copyPair, nonNullKills, definiteKills bool, macroWrites map[string]macros.WriteSummary) map[int]*nodeEffects {
	effects := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		effects[n.ID] = a.collectNodeEffects(n, genByLine, killByLine, dfgByLine, nonNullKills, definiteKills, macroWrites)
	}
	return effects
}

// collectNodeEffects extracts the transfer effects for a single statement node.
func (a *flowAnalyzer) collectNodeEffects(n *graph.StmtNode, genByLine, killByLine map[int][]string, dfgByLine map[int][]copyPair, nonNullKills, definiteKills bool, macroWrites map[string]macros.WriteSummary) *nodeEffects {
	e := &nodeEffects{gen: map[string]bool{}, kill: map[string]bool{}, copy: map[string]string{}}

	// gen/kill/DFG from the stored graph at this line — but only for LEAF
	// statements. A control-flow header (if/while/for/switch) shares its line
	// with a one-line body, so applying the line-keyed effects to the header
	// would leak the body's source/kill onto every branch.
	if !isControlFlowHeaderStmt(n.Stmt.Kind()) {
		for _, v := range genByLine[n.StartLine] {
			e.gen[v] = true
		}
		for _, v := range killByLine[n.StartLine] {
			e.kill[v] = true
		}
		for _, cp := range dfgByLine[n.StartLine] {
			e.copy[cp.lhs] = cp.rhs
		}
	}

	// AST-level copies/kills from the node's OWN statement (never recursing into
	// a branch/loop body, whose assignments belong to their own CFG nodes).
	for _, p := range directAssignments(n.Stmt) {
		name := assignTargetName(p.lhs)
		if name == "" {
			continue
		}
		if p.lhs.Kind() == "identifier" {
			if e.killBase == nil {
				e.killBase = map[string]bool{}
			}
			e.killBase[name] = true
		}
		if rv := copySourceKey(p.rhs); rv != "" {
			e.copy[name] = rv
		} else if nonNullKills || definiteKills {
			// Any reassignment other than a variable copy replaces the old value,
			// so it kills the old source. For the may-null tier a new possibly-
			// null source arrives as a gen event (malloc / external call /
			// nullable return); for the must-null tier a non-copy reassignment
			// always clears the CERTAIN-null fact.
			e.kill[name] = true
		}
	}

	// `&x` passed to a call is an output parameter: the callee may write x
	// through the pointer, so x's null state is reset at the call site. Without
	// this, `p = NULL; init(&p); p->f` (an initialized output-param) is
	// misread as a definite null-deref. The deref-arg kill (the second half of
	// addOutputParamKills) is null-deref specific, so it is gated on
	// nonNullKills: the taint source filter reuses this engine with
	// nonNullKills=false and must not lose copy taint through memcpy/strcpy.
	addOutputParamKills(n.Stmt, e, nonNullKills, macroWrites, a.iterMacros)

	return e
}

// addOutputParamKills records a kill for two shapes of call argument that prove
// a pointer's null source no longer holds at/after the call:
//
//   - `&x` passed as an argument (an output parameter): the callee may write x
//     through the pointer, resetting x's null state. This half is always on.
//   - a by-value pointer `p` passed to a library function that unconditionally
//     dereferences that argument position (`memset_s(head, ...)` writes `*head`):
//     reaching the next statement proves `p` was non-null, since the call would
//     otherwise have faulted. This half is gated on derefArgs because it is a
//     null-deref notion: the taint source filter shares this engine and its
//     memcpy/strcpy copy taint must survive (a copy is not a taint kill).
func addOutputParamKills(stmt parser.Node, e *nodeEffects, derefArgs bool, macroWrites map[string]macros.WriteSummary, iterMacros map[string][]int) {
	for _, call := range stmt.FindAll("call_expression") {
		children := call.NamedChildren()
		if len(children) < 2 {
			continue
		}
		argList := children[1]
		if argList.Kind() != "argument_list" {
			continue
		}
		derefIdxs, derefs := apikb.DerefArgs(callName(call))
		for i, arg := range argList.NamedChildren() {
			if name := addrTakenVar(arg); name != "" {
				e.kill[name] = true
				continue
			}
			if derefArgs && derefs && intIn(derefIdxs, i) {
				if name := rhsVarName(arg); name != "" {
					e.kill[name] = true
				}
			}
		}
		// A function-like macro that writes one of its arguments reassigns it
		// (`#define FOR_EACH(p) for ((p) = ...; (p); ...)` — a loop iterator
		// written in the init and null-checked in the condition). The previous
		// null source no longer reaches the dereference, so the written argument
		// is killed. Null-deref specific (gated on derefArgs) to match the
		// library-deref-arg kill above.
		if derefArgs {
			for name := range macros.WrittenArgs(call, macroWrites) {
				e.kill[name] = true
			}
			// A list-traversal macro (list_for_each_entry & friends from the
			// built-in apikb table, or a project-specific iterator macro
			// declared in secguard.toml [iterator_macros]) writes its iterator
			// parameter(s) in the for-init and null-guards them in the
			// condition. When the macro definition is outside the scan tree
			// (SDK header) the per-file macro analysis cannot see it, so the
			// iterator arguments are killed from the inlined knowledge base
			// merged with the config-declared set.
			if iterIdxs, ok := iterMacros[callName(call)]; ok {
				args := argList.NamedChildren()
				for _, i := range iterIdxs {
					if i >= len(args) {
						continue
					}
					if name := rhsVarName(args[i]); name != "" {
						e.kill[name] = true
					}
				}
			}
		}
	}
}

// macroWritesFor returns the per-macro write summaries for a file root, or nil
// when the analysis tier does not need macro-write kills (non-null kills are
// null-deref specific; taint and freed-state flows pass nonNullKills=false and
// must not pay the whole-tree walk). When the analyzer carries a whole-tree
// merged cache (a.macroWrites), it is used instead of the per-file root so a
// macro defined in a .h header is visible at call sites in every .c source.
func (a *flowAnalyzer) macroWritesFor(root parser.Node, nonNullKills bool) map[string]macros.WriteSummary {
	if !nonNullKills {
		return nil
	}
	if a.macroWrites != nil {
		return a.macroWrites
	}
	return macros.WriteSummaries(root)
}

// intIn reports whether v is an element of xs.
func intIn(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// addrTakenVar returns the variable whose address is taken by an argument,
// unwrapping cast expressions: `&x` and `(void **)&x` both yield "x". It returns
// "" for anything else (a by-value arg, a dereference, a field of x, ...).
func addrTakenVar(arg parser.Node) string {
	switch arg.Kind() {
	case "pointer_expression":
		if !strings.HasPrefix(strings.TrimSpace(arg.Text()), "&") {
			return ""
		}
		inner := arg.NamedChildren()
		if len(inner) == 0 || inner[0].Kind() != "identifier" {
			return ""
		}
		return inner[0].Text()
	case "cast_expression", "parenthesized_expression":
		for _, child := range arg.NamedChildren() {
			if name := addrTakenVar(child); name != "" {
				return name
			}
		}
	}
	return ""
}

// isControlFlowHeaderStmt reports whether a statement kind is a control-flow
// header (if/loop/switch/preprocessor conditional), as opposed to a leaf
// statement whose own line owns its effects.
func isControlFlowHeaderStmt(kind string) bool {
	switch kind {
	case "if_statement", "while_statement", "do_statement", "for_statement",
		"switch_statement", "preproc_ifdef", "preproc_ifndef", "preproc_if":
		return true
	}
	return false
}

// runDataflow runs the forward null-source reaching analysis. IN[entry] is
// empty (no variable is known null at function entry, matching the event-based
// source model), joins are unions of source-ID sets, and the transfer applies
// copy, kill, then gen. The lattice is monotone (source sets only grow at
// joins; a kill replaces a variable's set with the empty set, which is a fixed
// set-difference under union), so iteration order does not affect the fixpoint.
func runDataflow(cfg *graph.StmtCFG, effects map[int]*nodeEffects, entrySeeds map[string]bool) map[int]map[string]map[int]bool {
	nodeIn := make(map[int]map[string]map[int]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		nodeIn[i] = map[string]map[int]bool{}
	}

	// Seed the entry's IN with caller-influenced variables (function parameters
	// proven tainted by some caller). This makes the callee's intra-procedural
	// flow carry the inter-procedural context, so a sink on a LOCAL derived from
	// a tainted parameter is no longer a false negative.
	if len(entrySeeds) > 0 {
		for v := range entrySeeds {
			nodeIn[cfg.Entry][v] = map[int]bool{cfg.Entry: true}
		}
	}

	// Seed the worklist with every node, not just the entry: a node with a gen
	// effect adds facts regardless of its input, so it must be visited even
	// when its predecessor contributes nothing.
	worklist := make([]int, 0, len(cfg.Nodes))
	inQueue := make([]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		worklist = append(worklist, i)
		inQueue[i] = true
	}

	for len(worklist) > 0 {
		id := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		inQueue[id] = false

		out := transfer(nodeIn[id], effects[id], id)
		for _, succ := range cfg.Nodes[id].Succs {
			if mergeInto(nodeIn[succ], out) && !inQueue[succ] {
				inQueue[succ] = true
				worklist = append(worklist, succ)
			}
		}
	}
	return nodeIn
}

// transfer computes OUT = gen ∪ copy(in) ∪ (in \ kill), where in/out are
// source-ID sets keyed by variable and each gen source is identified by nodeID.
func transfer(in map[string]map[int]bool, e *nodeEffects, nodeID int) map[string]map[int]bool {
	out := make(map[string]map[int]bool, len(in)+4)
	for v, srcs := range in {
		out[v] = cloneSet(srcs)
	}
	if e == nil {
		return out
	}
	for lhs, rhs := range e.copy {
		out[lhs] = cloneSet(in[rhs])
	}
	for v := range e.kill {
		out[v] = map[int]bool{}
	}
	for base := range e.killBase {
		for k := range out {
			if isFieldOf(k, base) {
				out[k] = map[int]bool{}
			}
		}
	}
	for v := range e.gen {
		if out[v] == nil {
			out[v] = map[int]bool{}
		}
		out[v][nodeID] = true
	}
	return out
}

// isFieldOf reports whether key k names a field or element of base (p->f,
// p.f, or p[i]), which a whole-variable reassignment of base invalidates.
func isFieldOf(k, base string) bool {
	return strings.HasPrefix(k, base+"->") || strings.HasPrefix(k, base+".") || strings.HasPrefix(k, base+"[")
}

// mergeInto unions src into dst in place (per-variable source-set union) and
// reports whether dst changed.
func mergeInto(dst, src map[string]map[int]bool) bool {
	changed := false
	for v, srcs := range src {
		if len(srcs) == 0 {
			continue
		}
		if dst[v] == nil {
			dst[v] = map[int]bool{}
		}
		for s := range srcs {
			if !dst[v][s] {
				dst[v][s] = true
				changed = true
			}
		}
	}
	return changed
}

// runMustDataflow runs a forward BOOLEAN must analysis over the same CFG/effects
// shape as runDataflow. Unlike the may tier (union join, bottom = empty), the
// must tier joins with INTERSECTION and initializes non-entry nodes to TOP (the
// universe of variables that can ever hold the fact), so a fact survives only
// when every incoming path carries it. A kill on one branch therefore clears the
// fact at the join, which is exactly the semantics "certainly null" / "certainly
// freed" / "certainly uninitialized" require.
func runMustDataflow(cfg *graph.StmtCFG, effects map[int]*nodeEffects) (map[int]map[string]bool, map[int]map[string]bool) {
	// universe: every variable that appears in any effect (gen/kill/copy target
	// or source). TOP for a variable is "true on every path so far".
	universe := make(map[string]bool)
	for _, e := range effects {
		if e == nil {
			continue
		}
		for v := range e.gen {
			universe[v] = true
		}
		for v := range e.kill {
			universe[v] = true
		}
		for lhs, rhs := range e.copy {
			universe[lhs] = true
			universe[rhs] = true
		}
	}

	nodeIn := make(map[int]map[string]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		m := make(map[string]bool, len(universe))
		if i != cfg.Entry {
			for v := range universe {
				m[v] = true
			}
		}
		nodeIn[i] = m
	}

	// Only the entry is seeded; every other node starts at TOP and is lowered by
	// the intersection join as the entry's (empty) value propagates. Seeding all
	// nodes would keep TOP alive and falsely claim the fact holds everywhere.
	worklist := []int{cfg.Entry}
	inQueue := make([]bool, len(cfg.Nodes))
	inQueue[cfg.Entry] = true

	for len(worklist) > 0 {
		id := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		inQueue[id] = false

		out := mustTransfer(nodeIn[id], effects[id])
		for _, succ := range cfg.Nodes[id].Succs {
			if mustMergeInto(nodeIn[succ], out) && !inQueue[succ] {
				inQueue[succ] = true
				worklist = append(worklist, succ)
			}
		}
	}

	genAt := make(map[int]map[string]bool)
	for id, e := range effects {
		if e != nil && len(e.gen) > 0 {
			m := make(map[string]bool, len(e.gen))
			for v := range e.gen {
				m[v] = true
			}
			genAt[id] = m
		}
	}
	return nodeIn, genAt
}

// mustTransfer computes OUT for a boolean must node: copy propagates the source's
// fact, kill clears it, gen sets it. Order is copy, then kill, then gen.
func mustTransfer(in map[string]bool, e *nodeEffects) map[string]bool {
	out := make(map[string]bool, len(in))
	for v, b := range in {
		out[v] = b
	}
	if e == nil {
		return out
	}
	for lhs, rhs := range e.copy {
		out[lhs] = in[rhs]
	}
	for v := range e.kill {
		out[v] = false
	}
	for base := range e.killBase {
		for k := range out {
			if isFieldOf(k, base) {
				out[k] = false
			}
		}
	}
	for v := range e.gen {
		out[v] = true
	}
	return out
}

// mustMergeInto intersects src into dst in place (boolean AND) and reports
// whether dst changed. A variable absent from src means false on that path.
func mustMergeInto(dst, src map[string]bool) bool {
	changed := false
	for v, b := range dst {
		if !b {
			continue // already false; AND with anything stays false
		}
		if !src[v] {
			dst[v] = false
			changed = true
		}
	}
	return changed
}

func cloneSet(src map[int]bool) map[int]bool {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[int]bool, len(src))
	for s := range src {
		dst[s] = true
	}
	return dst
}

func genAt(cfg *graph.StmtCFG, effects map[int]*nodeEffects) map[int]map[string]bool {
	genAt := make(map[int]map[string]bool, len(cfg.Nodes))
	for id, e := range effects {
		if e != nil && len(e.gen) > 0 {
			genAt[id] = e.gen
		}
	}
	return genAt
}

// forEachAssignment visits every (lhs, rhs) pair of an assignment_expression or
// init_declarator inside a statement.
func forEachAssignment(stmt parser.Node, fn func(lhs, rhs parser.Node)) {
	for _, assign := range stmt.FindAll("assignment_expression") {
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		fn(children[0], children[1])
	}
	for _, init := range stmt.FindAll("init_declarator") {
		children := init.NamedChildren()
		if len(children) < 2 {
			continue
		}
		fn(children[0], children[1])
	}
}

// assignTargetName returns the tracked variable name an assignment writes to,
// matching the evidence detectors' naming (field/subscript paths keep their full
// text). Writing through a dereference (`*p = ...`) returns "" because it does
// not change p itself.
func assignTargetName(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		return lhs.Text()
	case "field_expression", "subscript_expression":
		return lhs.Text()
	case "pointer_declarator", "array_declarator", "function_declarator":
		return declaratorName(lhs)
	}
	return ""
}

// declaratorName extracts the identifier a declarator names.
func declaratorName(n parser.Node) string {
	if n.Kind() == "identifier" {
		return n.Text()
	}
	for _, c := range n.NamedChildren() {
		if c.Kind() == "identifier" {
			return c.Text()
		}
		if name := declaratorName(c); name != "" {
			return name
		}
	}
	return ""
}

// rhsVarName returns the variable name when rhs is a bare identifier (possibly
// wrapped in parentheses or a cast), else "".
func rhsVarName(rhs parser.Node) string {
	switch rhs.Kind() {
	case "identifier":
		return rhs.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range rhs.NamedChildren() {
			if name := rhsVarName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

// copySourceKey returns the field-qualified location a value copies FROM, so
// `q = p->f` propagates the nullness of location p->f (not the whole p), and
// `q = a[i]` propagates location a[i]. It matches the detector's text-based
// keys (`p->f`, `p[i]`) so a NULL_VALUE source and a later copy/deref resolve to
// the same location. Bare `p` is the whole-variable location.
func copySourceKey(rhs parser.Node) string {
	switch rhs.Kind() {
	case "identifier", "field_expression", "subscript_expression":
		return rhs.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range rhs.NamedChildren() {
			if k := copySourceKey(c); k != "" {
				return k
			}
		}
	}
	return ""
}

// loadDFGCopies resolves all stored DATA_FLOW edges into per-function, per-line
// copy pairs. It is a best-effort read of the graph layer: on any error it
// returns an empty map and the analysis continues on CFG + events alone.
func (a *flowAnalyzer) loadDFGCopies(ctx context.Context, funcIDs []int64) map[int64]map[int][]copyPair {
	result := make(map[int64]map[int][]copyPair)
	edges, err := a.store.ListGraphEdgesByType(ctx, "DATA_FLOW")
	if err != nil {
		return result
	}

	// Resolve variable_ref node IDs to (function, name, line), but only for
	// functions we actually analyze. One bulk query for every variable_ref node
	// (rather than one query per function) avoids an N+1 query storm over a
	// large codebase.
	want := make(map[int64]bool, len(funcIDs))
	for _, fid := range funcIDs {
		want[fid] = true
	}
	nameByNode := make(map[int64]string)
	lineByNode := make(map[int64]int)
	funcByNode := make(map[int64]int64)
	nodes, err := a.store.ListGraphNodesByEntityType(ctx, "variable_ref")
	if err != nil {
		return result
	}
	for _, n := range nodes {
		if !want[n.EntityID] {
			continue
		}
		var props struct {
			Name string `json:"name"`
			Line int    `json:"line"`
		}
		if json.Unmarshal([]byte(n.Properties), &props) != nil || props.Name == "" {
			continue
		}
		nameByNode[n.ID] = props.Name
		lineByNode[n.ID] = props.Line
		funcByNode[n.ID] = n.EntityID
	}

	for _, e := range edges {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		rhs, ok := nameByNode[e.SrcID]
		if !ok {
			continue
		}
		fid, ok := funcByNode[e.SrcID]
		if !ok {
			continue
		}
		lhs, ok := nameByNode[e.DstID]
		if !ok || lhs == "" {
			lhs = props.Variable
		}
		if lhs == "" || lhs == rhs {
			continue
		}
		if result[fid] == nil {
			result[fid] = make(map[int][]copyPair)
		}
		line := lineByNode[e.SrcID]
		result[fid][line] = append(result[fid][line], copyPair{lhs: lhs, rhs: rhs})
	}

	return result
}

// loadAliases resolves stored ALIAS edges into a per-function map from base
// variable to the list of variables that alias it. The freed-state flow filters
// use this to propagate a freed source from a variable to its aliases (freeing
// p dangles every q that aliases p). Best-effort: on any error it returns an
// empty map and the analysis continues on the AST-level copy step alone.
func (a *flowAnalyzer) loadAliases(ctx context.Context, funcIDs []int64) map[int64]map[string][]string {
	result := make(map[int64]map[string][]string)
	edges, err := a.store.ListGraphEdgesByType(ctx, "ALIAS")
	if err != nil {
		return result
	}

	want := make(map[int64]bool, len(funcIDs))
	for _, fid := range funcIDs {
		want[fid] = true
	}

	nameByNode := make(map[int64]string)
	funcByNode := make(map[int64]int64)
	nodes, err := a.store.ListGraphNodesByEntityType(ctx, "variable_ref")
	if err != nil {
		return result
	}
	for _, n := range nodes {
		if !want[n.EntityID] {
			continue
		}
		var props struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(n.Properties), &props) != nil || props.Name == "" {
			continue
		}
		nameByNode[n.ID] = props.Name
		funcByNode[n.ID] = n.EntityID
	}

	for _, e := range edges {
		// A field/element alias (q = p->f, q = p[i]) copies a FIELD value, not the
		// base pointer itself, so freeing p does NOT dangle q. Only whole-variable
		// aliases (field == "") must propagate the freed state. Treating field
		// aliases as whole-variable aliases produced use-after-free false
		// positives (e.g. q = p->f; free(p); use(q) when p->f is a plain int).
		var props struct {
			Field string `json:"field"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props.Field != "" {
			continue
		}
		alias := nameByNode[e.SrcID]
		base := nameByNode[e.DstID]
		fid := funcByNode[e.SrcID]
		if alias == "" || base == "" || alias == base {
			continue
		}
		if result[fid] == nil {
			result[fid] = make(map[string][]string)
		}
		result[fid][base] = append(result[fid][base], alias)
	}
	return result
}

// expandGenToAliases adds, for every variable that generates a source, its alias
// variables at the same line. Used only by the freed-state analyses (use-after-
// free / double-free): free(p) invalidates the OBJECT p points to, so every
// variable aliasing p is also dangling — regardless of when the alias was
// created. It is deliberately NOT applied to null-deref, where nullness is a
// property of the pointer's current VALUE (q = p; p = NULL leaves q non-null).
func expandGenToAliases(genByLine map[int][]string, aliasesOf map[string][]string) {
	if len(aliasesOf) == 0 {
		return
	}
	for line, vars := range genByLine {
		var extra []string
		for _, v := range vars {
			extra = append(extra, aliasesOf[v]...)
		}
		if len(extra) > 0 {
			genByLine[line] = append(genByLine[line], extra...)
		}
	}
}

// loadFreeSites resolves stored RELEASE edges with release_fn == "free" into a
// per-function, per-line map of directly-freed variables. It is the graph-native
// source of DIRECT memory free sites for the freed-state flow filters (UAF /
// double-free), so the semantic graph's RELEASE edges are finally consumed. The
// release_fn filter is what makes the consumption precise: memory free (free)
// is routed to the memory flow, while resource releases (fclose/close) are left
// to the resource-leak pipeline.
//
// Indirect free sites (a callee frees a parameter) have no RELEASE edge, so the
// filters keep seeding those from the detector's event properties.
func (a *flowAnalyzer) loadFreeSites(ctx context.Context, funcIDs []int64) map[int64]map[int][]string {
	result := make(map[int64]map[int][]string)
	edges, err := a.store.ListGraphEdgesByType(ctx, "RELEASE")
	if err != nil {
		return result
	}

	want := make(map[int64]bool, len(funcIDs))
	for _, fid := range funcIDs {
		want[fid] = true
	}
	nameByNode := make(map[int64]string)
	lineByNode := make(map[int64]int)
	funcByNode := make(map[int64]int64)
	nodes, err := a.store.ListGraphNodesByEntityType(ctx, "variable_ref")
	if err != nil {
		return result
	}
	for _, n := range nodes {
		if !want[n.EntityID] {
			continue
		}
		var props struct {
			Name string `json:"name"`
			Line int    `json:"line"`
		}
		if json.Unmarshal([]byte(n.Properties), &props) != nil || props.Name == "" {
			continue
		}
		nameByNode[n.ID] = props.Name
		lineByNode[n.ID] = props.Line
		funcByNode[n.ID] = n.EntityID
	}

	for _, e := range edges {
		var props struct {
			ReleaseFn string `json:"release_fn"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) != nil || props.ReleaseFn != "free" {
			continue
		}
		name := nameByNode[e.SrcID]
		fid := funcByNode[e.SrcID]
		if name == "" || fid == 0 {
			continue
		}
		if result[fid] == nil {
			result[fid] = make(map[int][]string)
		}
		result[fid][lineByNode[e.SrcID]] = append(result[fid][lineByNode[e.SrcID]], name)
	}
	return result
}

// freeAlreadySeeded reports whether genByLine already records variable as freed
// at line — used to avoid double-seeding a direct free site that both the
// RELEASE edges and the detector's event properties capture.
func freeAlreadySeeded(genByLine map[int][]string, line int, variable string) bool {
	for _, v := range genByLine[line] {
		if v == variable {
			return true
		}
	}
	return false
}

// callResultNullSources returns the possible-null sources introduced by `p = f()`
// where f is a known possibly-null-returning function. These are synthesized in
// the planner (not emitted as NULL_VALUE events) because the detector only
// recognizes a literal `return NULL`; a function that returns a possibly-null
// variable, an allocator, or another nullable callee is only discoverable via
// the RETURN edges + intra-procedural flow, which the planner owns.
func callResultNullSources(body parser.Node, retNullable map[string]bool) []nullSource {
	if len(retNullable) == 0 {
		return nil
	}
	var out []nullSource
	forEachAssignment(body, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" {
			return
		}
		callee := rhsCallName(rhs)
		if callee == "" || !retNullable[callee] {
			return
		}
		out = append(out, nullSource{variable: name, line: rhs.StartLine(), origin: "external_call", definite: false})
	})
	return out
}

// returnsNullable reports whether body can return a possibly-null pointer: a
// NULL literal, an allocator call, a pointer parameter, a variable with a
// reaching may-null source, or a call to another possibly-null-returning
// function.
func returnsNullable(body parser.Node, flow *flowResult, params map[string]int, retNullable map[string]bool) bool {
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		if exprReturnsNullable(children[0], flow, params, retNullable, ret.StartLine()) {
			return true
		}
	}
	return false
}

func exprReturnsNullable(expr parser.Node, flow *flowResult, params map[string]int, retNullable map[string]bool, line int) bool {
	if isNullLiteralExpr(expr.Text()) {
		return true
	}
	switch expr.Kind() {
	case "call_expression":
		name := callName(expr)
		return isAllocatorCall(name) || retNullable[name]
	case "identifier":
		if _, isParam := params[expr.Text()]; isParam {
			return true
		}
		return flow != nil && flow.reaching(expr.Text(), line)
	case "cast_expression", "parenthesized_expression":
		for _, c := range expr.NamedChildren() {
			if exprReturnsNullable(c, flow, params, retNullable, line) {
				return true
			}
		}
	}
	return false
}

func isNullLiteralExpr(text string) bool {
	t := strings.TrimSpace(text)
	switch t {
	case "NULL", "nullptr", "(void*)0", "(void *)0", "((void*)0)", "((void *)0)":
		return true
	}
	return false
}

// mayReturnPointer reports whether a function body could return a pointer value.
// It is a cheap pre-filter for computeRetNullable: a return statement whose
// expression is a non-pointer literal (int/char/bool/sizeof) cannot yield a NULL
// pointer, so the function can be skipped without running the flow analysis.
// Everything else — identifiers (a pointer parameter), calls (an allocator or a
// nullable callee), casts/parens (which may wrap a pointer), field/subscript
// (a pointer member), unary/pointer/conditional/binary — is conservatively
// treated as "may return a pointer" so the filter never drops a real nullable
// returner.
func mayReturnPointer(body parser.Node) bool {
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		expr := children[0]
		if isNullLiteralExpr(expr.Text()) {
			return true
		}
		switch expr.Kind() {
		case "number_literal", "char_literal", "true", "false", "sizeof_expression":
			continue
		default:
			return true
		}
	}
	return false
}

func isAllocatorCall(name string) bool {
	switch name {
	case "malloc", "calloc", "realloc":
		return true
	}
	return false
}

// fileParseCache lazily parses each file once and caches its root plus a map
// from function-definition start line to the function's compound_statement
// body. It replaces the per-function readFunctionBody, which re-walked the
// whole tree looking for function_definition once per function — a dominant
// remaining cost of the flow filters over a large codebase.
type fileParseCache struct {
	parser *parser.Parser
	roots  map[int64]parser.Node
	bodies map[int64]map[int]parser.Node
}

func newFileParseCache(p *parser.Parser) *fileParseCache {
	return &fileParseCache{parser: p, roots: make(map[int64]parser.Node), bodies: make(map[int64]map[int]parser.Node)}
}

// get returns fn's compound_statement body and the file root, parsing the file
// at most once. The (body, root) order matches the old readFunctionBody.
func (fc *fileParseCache) get(file *db.File, fn *db.Function) (parser.Node, parser.Node) {
	bodies, ok := fc.bodies[file.ID]
	if !ok {
		root, m := functionBodiesForFile(fc.parser, file)
		fc.roots[file.ID] = root
		fc.bodies[file.ID] = m
		bodies = m
	}
	return bodies[fn.StartLine], fc.roots[file.ID]
}

// rootForFile returns the parsed file root, parsing at most once. It is the
// file-level analogue of get, for callers that need the whole tree (e.g. to
// collect macro definitions) without a specific function.
func (fc *fileParseCache) rootForFile(file *db.File) parser.Node {
	if root, ok := fc.roots[file.ID]; ok {
		return root
	}
	root, m := functionBodiesForFile(fc.parser, file)
	fc.roots[file.ID] = root
	fc.bodies[file.ID] = m
	return root
}

// functionBodiesForFile parses file and returns its root plus a map from each
// function definition's start line to its compound_statement body.
func functionBodiesForFile(p *parser.Parser, file *db.File) (parser.Node, map[int]parser.Node) {
	source, err := os.ReadFile(file.Path)
	if err != nil {
		return parser.Node{}, nil
	}
	tree, err := p.ParseCached(source, file.Path)
	if err != nil {
		return parser.Node{}, nil
	}
	root := tree.RootNode()
	bodies := make(map[int]parser.Node)
	for _, def := range root.FindAll("function_definition") {
		if body := def.FindFirst("compound_statement"); body != nil {
			bodies[def.StartLine()] = *body
		}
	}
	return root, bodies
}
