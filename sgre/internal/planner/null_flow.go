package planner

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
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

func (m *flowResult) weakGuardAt(variable string, line int) bool {
	if m == nil || m.weakGuard == nil {
		return false
	}
	n := m.cfg.NodeAt(line)
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
	if res != nil && (len(definiteGenByLine) > 0 || len(a.definiteEntrySeeds) > 0) {
		res.definite, res.definiteGenAt = a.analyzeDefiniteNull(res.cfg, fileRoot, a.scopeOracle(body), a.definiteEntrySeeds)
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

	cfg := graph.BuildStmtCFGWithCache(a.cfgCache, fn.ID, body, fn.EndLine)
	effects := a.buildEffects(cfg, genByLine, killByLine, a.dfgCopies[fn.ID], nonNullKills, definiteKills, a.macroWritesFor(fileRoot, nonNullKills), a.scopeOracle(body))
	// Null guards are path-sensitive kills; they apply only to the null-deref
	// may-analysis (nonNullKills), never to taint/freed-state/uninit flows.
	var guard *guardModel
	if nonNullKills {
		guard = buildGuardModel(cfg, a.helperParams, a.macroGuards)
	}
	nodeIn := runDataflow(cfg, effects, a.entrySeeds, guard)
	return &flowResult{cfg: cfg, nodeIn: nodeIn, genAt: genAt(cfg, effects), weakGuard: buildWeakGuardMap(cfg), ternaryGuard: buildTernaryGuardMap(body)}
}

// analyzeFlowMust runs the may reaching-sources dataflow and, over the SAME
// effects, the boolean must dataflow. It is used by the freed-state / uninit
// filters, which need both: may to keep candidates, must to promote a kept
// candidate to "confirmed" only when the fact reaches the use on every path.
func (a *flowAnalyzer) analyzeFlowMust(ctx context.Context, fn *db.Function, body parser.Node, fileRoot parser.Node, genByLine, killByLine map[int][]string, nonNullKills, definiteKills bool) *flowResult {
	if body.Kind() != "compound_statement" {
		return nil
	}

	cfg := graph.BuildStmtCFGWithCache(a.cfgCache, fn.ID, body, fn.EndLine)
	effects := a.buildEffects(cfg, genByLine, killByLine, a.dfgCopies[fn.ID], nonNullKills, definiteKills, a.macroWritesFor(fileRoot, nonNullKills), a.scopeOracle(body))
	res := &flowResult{cfg: cfg, nodeIn: runDataflow(cfg, effects, a.entrySeeds, nil), genAt: genAt(cfg, effects)}
	res.must, res.mustGenAt = runMustDataflow(cfg, effects, nil)
	return res
}

// analyzeDefiniteNull runs the boolean must-null dataflow for the null definite
// tier. Its effects are derived NODE-PRECISELY from each statement's own
// assignments (not from a line-keyed source map): gen = `p = NULL`, kill = any
// other non-copy reassignment, copy = `p = q`. A line-keyed map would collide
// when a one-line `if (c) p = NULL; else p = &x;` puts both the header and its
// branches on one line, falsely assigning the NULL gen to the `p = &x` branch.
func (a *flowAnalyzer) analyzeDefiniteNull(cfg *graph.StmtCFG, fileRoot parser.Node, isValue func(string) bool, entrySeeds map[string]bool) (map[int]map[string]bool, map[int]map[string]bool) {
	macroWrites := a.macroWritesFor(fileRoot, true)
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
			if isNullLiteralNode(p.rhs) {
				e.gen[name] = true
			} else if rv := copySourceKey(p.rhs); rv != "" {
				e.copy[name] = rv
			} else {
				e.kill[name] = true
			}
		}
		addOutputParamKills(n.Stmt, e, true, macroWrites, a.iterMacros, isValue)
		effects[n.ID] = e
	}
	return runMustDataflow(cfg, effects, entrySeeds)
}

// buildEffects computes the per-statement-node transfer effects for a CFG.
func (a *flowAnalyzer) buildEffects(cfg *graph.StmtCFG, genByLine, killByLine map[int][]string, dfgByLine map[int][]copyPair, nonNullKills, definiteKills bool, macroWrites map[string]macros.WriteSummary, isValue func(string) bool) map[int]*nodeEffects {
	effects := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		effects[n.ID] = a.collectNodeEffects(n, genByLine, killByLine, dfgByLine, nonNullKills, definiteKills, macroWrites, isValue)
	}
	return effects
}

// collectNodeEffects extracts the transfer effects for a single statement node.
func (a *flowAnalyzer) collectNodeEffects(n *graph.StmtNode, genByLine, killByLine map[int][]string, dfgByLine map[int][]copyPair, nonNullKills, definiteKills bool, macroWrites map[string]macros.WriteSummary, isValue func(string) bool) *nodeEffects {
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
	addOutputParamKills(n.Stmt, e, nonNullKills, macroWrites, a.iterMacros, isValue)

	// A field/subscript-read copy (`q = p->f`, `q = (T*)p->f`) propagates the
	// base pointer's null sources to q in addition to the field location's own:
	// a value read through a possibly-null base is itself possibly-null. This is
	// the null-deref analogue of the field-sensitive whole-variable copy and is
	// what lets `tree = (T*)(resp->group_data); tree[0]` inherit resp's
	// caller-null source (the derived pointer would otherwise have no source).
	if nonNullKills {
		for lhs, rhs := range e.copy {
			if base := fieldBaseName(rhs); base != "" {
				if e.copyFieldBase == nil {
					e.copyFieldBase = make(map[string]string)
				}
				e.copyFieldBase[lhs] = base
			}
		}
	}

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
func addOutputParamKills(stmt parser.Node, e *nodeEffects, derefArgs bool, macroWrites map[string]macros.WriteSummary, iterMacros map[string][]int, isValue func(string) bool) {
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
			if name := addrTakenVar(arg, isValue); name != "" {
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

	// A function-like macro whose argument is a TYPE cast parses as an ERROR
	// node (a type is not an expression), so FindAll("call_expression") above
	// misses it. Recover the name + positional arguments from the ERROR form so
	// the macro-write and iterator kills still fire for `MACRO(list, iter,
	// type *)` — the iterator is written in the for-init and null-guarded by the
	// loop condition, so its null source must be killed at the call site.
	if derefArgs {
		for _, errNode := range stmt.FindAll("ERROR") {
			name, args := macroCallFromError(errNode)
			if name == "" {
				continue
			}
			for _, v := range macros.WrittenArgsInError(name, args, macroWrites) {
				e.kill[v] = true
			}
			if iterIdxs, ok := iterMacros[name]; ok {
				for _, i := range iterIdxs {
					if i >= len(args) {
						continue
					}
					if v := rhsVarName(args[i]); v != "" {
						e.kill[v] = true
					}
				}
			}
		}
	}
}

// macroCallFromError recovers a function-like macro call that tree-sitter parsed
// as an ERROR node rather than a call_expression. This happens when a macro
// argument is a TYPE cast (`SINGLE_LINKEDLIST_Scan(list, iter, type *)`): a type
// is not a valid expression, so the whole call plus its loop body becomes an
// ERROR node whose named children are [macro-name, arg0, arg1, ...] with an
// optional trailing compound_statement (the body). It returns the macro name and
// the positional arguments (body excluded), or ("", nil) when the node is not
// that shape.
func macroCallFromError(stmt parser.Node) (string, []parser.Node) {
	if stmt.Kind() != "ERROR" {
		return "", nil
	}
	children := stmt.NamedChildren()
	if len(children) == 0 || children[0].Kind() != "identifier" {
		return "", nil
	}
	name := children[0].Text()
	var args []parser.Node
	for _, c := range children[1:] {
		if c.Kind() == "compound_statement" {
			break
		}
		args = append(args, c)
	}
	if len(args) == 0 {
		return "", nil
	}
	return name, args
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

// addrTakenVar returns the variable whose address is taken by a call argument,
// covering the spellings parser.Node.AddressTakenTarget recognizes: `&x`,
// `&(x)`, `(void **)&x` and `(T)&x` parsed as a bit-and binary_expression
// (`(shm_handle)&prfs_list` — tree-sitter-c has no typedef table, so the
// argument has no pointer_expression child and the address-of used to be
// invisible, keeping the caller's definite null alive past the call). It
// returns "" for anything else (a by-value arg, a dereference, a field of x,
// ...): only a whole-variable address proves the callee may reassign x itself.
//
// isValue is the scope oracle that keeps a genuine bit-and argument
// (`f((flags) & p)`) from being read as `&p` and killing p's null state; see
// parser.Node.AddressTakenTargetScoped. A nil oracle falls back to the
// permissive recognition.
func addrTakenVar(arg parser.Node, isValue func(string) bool) string {
	target, ok := arg.AddressTakenTargetScoped(isValue)
	if !ok || target.Kind() != "identifier" {
		return ""
	}
	return target.Text()
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
func runDataflow(cfg *graph.StmtCFG, effects map[int]*nodeEffects, entrySeeds map[string]bool, guard *guardModel) map[int]map[string]map[int]bool {
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
			o := out
			if guard != nil {
				if gk := guard.edgeKills[[2]int{id, succ}]; len(gk) > 0 {
					// A guard kills a variable's null source only on this edge, so
					// clone the shared OUT before mutating it.
					o = make(map[string]map[int]bool, len(out))
					for v, srcs := range out {
						o[v] = srcs
					}
					for v := range gk {
						o[v] = map[int]bool{}
					}
				}
			}
			if mergeInto(nodeIn[succ], o) && !inQueue[succ] {
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
	for lhs, base := range e.copyFieldBase {
		if out[lhs] == nil {
			out[lhs] = map[int]bool{}
		}
		for s := range in[base] {
			out[lhs][s] = true
		}
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
func runMustDataflow(cfg *graph.StmtCFG, effects map[int]*nodeEffects, entrySeeds map[string]bool) (map[int]map[string]bool, map[int]map[string]bool) {
	// universe: every variable that appears in any effect (gen/kill/copy target
	// or source). TOP for a variable is "true on every path so far". Entry seeds
	// are added so a parameter proven null by a caller is tracked even when the
	// callee body has no assignment of it.
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
	for v := range entrySeeds {
		universe[v] = true
	}

	nodeIn := make(map[int]map[string]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		m := make(map[string]bool, len(universe))
		if i != cfg.Entry {
			for v := range universe {
				m[v] = true
			}
		} else {
			for v := range entrySeeds {
				m[v] = true
			}
		}
		nodeIn[i] = m
	}

	// Seed the worklist with EVERY node, not just the entry. A node with a gen
	// (`p = NULL`) or kill (`p = f()`) effect introduces a fact regardless of its
	// input, so it must be visited even when its predecessor contributes nothing;
	// and a control-flow header (if/while) with no own effect must still forward
	// its predecessor's fact to its branches — otherwise a kill inside the branch
	// is never reached and a reassignment after `p = NULL` fails to clear the
	// certain-null fact. This mirrors runRangeDataflow's seed-every-node.
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

func buildWeakGuardMap(cfg *graph.StmtCFG) map[int]map[string]bool {
	out := make(map[int]map[string]bool)
	if cfg == nil {
		return out
	}
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" || !isConditionKind(n.Stmt.Kind()) {
			continue
		}
		cond := n.Stmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		for _, v := range parser.NullCheckedVars(*cond) {
			if out[n.ID] == nil {
				out[n.ID] = map[string]bool{}
			}
			out[n.ID][v] = true
		}
	}
	return out
}

// ternaryGuardEntry is one dereference point proven non-null by a conditional
// expression's guard: `p != NULL ? p->f : d` proves p non-null for the `p->f`
// dereference inside the consequence (true branch); `p == NULL ? d : p->f`
// proves it for the alternative (false branch). The entry records the exact
// dereference line, so a same-line `p == NULL ? p->a : 0` (the NULL-path
// dereference in the consequence) is NOT guarded by the alternative-side guard.
type ternaryGuardEntry struct {
	variable string
	line     int
}

// buildTernaryGuardMap collects the null-guarded dereference points of every
// conditional expression in a function body. A conditional expression stays
// inside one straight-line CFG node, so these guards cannot ride the edge-kill
// model; the guarded branch's own dereference sites are recorded from the AST
// (base-precise, line-precise) and resolved at the nullable-source convergence
// stage. Only dereferences whose BASE is exactly the guarded variable match:
// `p->a->b` contributes the inner `p->a` read (base p), which is what a guard
// on p protects.
func buildTernaryGuardMap(body parser.Node) []ternaryGuardEntry {
	if body.Kind() != "compound_statement" {
		return nil
	}
	var out []ternaryGuardEntry
	for _, ce := range body.FindAll("conditional_expression") {
		cond := ce.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if cons := ce.ChildByFieldName("consequence"); cons != nil {
			for _, v := range parser.GuardedNonnullVars(*cond) {
				out = append(out, guardedDerefEntries(*cons, v)...)
			}
		}
		if alt := ce.ChildByFieldName("alternative"); alt != nil {
			for _, v := range parser.NullCheckedVars(*cond) {
				out = append(out, guardedDerefEntries(*alt, v)...)
			}
		}
	}
	return out
}

// guardedDerefEntries finds branch's dereference points of variable: field
// accesses (`v->f`, including the inner read of `v->f->g`), pointer
// dereferences (`*v`), and subscripts (`v[i]`) whose base is exactly variable.
func guardedDerefEntries(branch parser.Node, variable string) []ternaryGuardEntry {
	var out []ternaryGuardEntry
	for _, fe := range branch.FindAll("field_expression") {
		base := stripGuardCasts(derefGuardBaseChild(fe))
		if base.Kind() == "identifier" && base.Text() == variable {
			out = append(out, ternaryGuardEntry{variable: variable, line: fe.StartLine()})
		}
	}
	for _, pd := range branch.FindAll("pointer_expression") {
		// pointer_expression covers both `*p` (deref) and `&x` (address-of);
		// only the deref is a null-deref sink, so skip the address-of form.
		if strings.HasPrefix(strings.TrimSpace(pd.Text()), "&") {
			continue
		}
		kids := pd.NamedChildren()
		if len(kids) == 1 {
			inner := stripGuardCasts(kids[0])
			if inner.Kind() == "identifier" && inner.Text() == variable {
				out = append(out, ternaryGuardEntry{variable: variable, line: pd.StartLine()})
			}
		}
	}
	for _, se := range branch.FindAll("subscript_expression") {
		kids := se.NamedChildren()
		if len(kids) >= 1 {
			base := stripGuardCasts(kids[0])
			if base.Kind() == "identifier" && base.Text() == variable {
				out = append(out, ternaryGuardEntry{variable: variable, line: se.StartLine()})
			}
		}
	}
	return out
}

// stripGuardCasts unwraps cast and parenthesized expressions down to the
// operand (a local twin of evidence's stripCasts, kept in-package so the
// planner does not reach into evidence internals).
func stripGuardCasts(n parser.Node) parser.Node {
	for n.Kind() == "cast_expression" || n.Kind() == "parenthesized_expression" {
		next := parser.Node{}
		for _, c := range n.NamedChildren() {
			if c.Kind() == "type_descriptor" {
				continue
			}
			next = c
			break
		}
		if next.Kind() == "" {
			return n
		}
		n = next
	}
	return n
}

// derefGuardBaseChild returns the base operand of a field/subscript
// expression (the dereferenced pointer), or a zero Node.
func derefGuardBaseChild(n parser.Node) parser.Node {
	if n.Kind() != "field_expression" && n.Kind() != "subscript_expression" {
		return parser.Node{}
	}
	kids := n.NamedChildren()
	if len(kids) == 0 {
		return parser.Node{}
	}
	return kids[0]
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
		if lhs, rhs, ok := init.AssignParts(); ok {
			fn(lhs, rhs)
		}
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

// fieldBaseName returns the base variable of a field/subscript location key
// (`p->f`, `p[i]`, `s.f`, `p->a->b`), or "" when the key is a bare variable or
// not a field/subscript path. It is the identifier before the first member or
// subscript access, so a chained path yields its top-level base. The base is
// trimmed so a spaced `p -> f` still resolves to the parameter name `p`.
func fieldBaseName(key string) string {
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '-':
			if i+1 < len(key) && key[i+1] == '>' {
				return strings.TrimSpace(key[:i])
			}
		case '.', '[':
			return strings.TrimSpace(key[:i])
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

// aliasSite is one whole-variable alias assignment: the aliasing variable was
// assigned `base` (`alias = base`) at line. The line is what makes the freed-
// state alias propagation flow-sensitive: an alias only dangles a freed source
// when its MOST RECENT assignment on or before the free still aliases the freed
// variable (a later `alias = other` breaks the alias and must not propagate it).
type aliasSite struct {
	base string
	line int
}

// loadAliases resolves stored ALIAS edges into a per-function map from aliasing
// variable to the list of (base, line) it was assigned. The freed-state flow
// filters use this to propagate a freed source from a variable to the variables
// that STILL alias it at the free line (freeing p dangles a q that is currently
// p; a q reassigned to something else before the free is not dangled). Best-
// effort: on any error it returns an empty map and the analysis continues on the
// AST-level copy step alone.
func (a *flowAnalyzer) loadAliases(ctx context.Context, funcIDs []int64) map[int64]map[string][]aliasSite {
	result := make(map[int64]map[string][]aliasSite)
	edges, err := a.store.ListGraphEdgesByType(ctx, "ALIAS")
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
			result[fid] = make(map[string][]aliasSite)
		}
		result[fid][alias] = append(result[fid][alias], aliasSite{base: base, line: lineByNode[e.SrcID]})
	}
	return result
}

// expandGenToAliases adds, for every variable that generates a source, the
// variables that STILL alias it at the source line. Used only by the freed-state
// analyses (use-after-free / double-free): free(p) invalidates the OBJECT p
// points to, so a variable q that currently aliases p is also dangling. The
// "currently" is the key word: an alias q = p established at line 10 is broken
// by a later q = other at line 20, so a free(p) at line 25 must NOT dangle q.
// The flow-sensitive check is latestAliasBase: among q's alias assignments on
// or before the free line, the most recent one's base must equal p for q to be
// dangled. It is deliberately NOT applied to null-deref, where nullness is a
// property of the pointer's current VALUE (q = p; p = NULL leaves q non-null).
func expandGenToAliases(genByLine map[int][]string, aliasesOf map[string][]aliasSite) {
	if len(aliasesOf) == 0 {
		return
	}
	for line, vars := range genByLine {
		var extra []string
		for _, v := range vars {
			for alias, sites := range aliasesOf {
				if base, ok := latestAliasBase(sites, line); ok && base == v {
					extra = append(extra, alias)
				}
			}
		}
		if len(extra) > 0 {
			genByLine[line] = append(genByLine[line], extra...)
		}
	}
}

// latestAliasBase returns the base of the most recent alias assignment at or
// before line. An alias assignment (alias = base) at line 10 is superseded by a
// later one at line 20, so only the last one on or before the query line
// determines what alias currently names. If no assignment is on or before line,
// the variable did not yet alias anything and the second return is false.
func latestAliasBase(sites []aliasSite, line int) (string, bool) {
	var best *aliasSite
	for i := range sites {
		s := &sites[i]
		if s.line > line {
			continue
		}
		if best == nil || s.line > best.line {
			best = s
		}
	}
	if best == nil {
		return "", false
	}
	return best.base, true
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
// the RETURN edges + intra-procedural flow, which the planner owns. The origin
// carries the CALLEE NAME (not the "external_call" marker): the nullable-source
// filter reads it back to tell an in-scan callee — whose body the report can
// embed — from a genuinely external one.
func callResultNullSources(body parser.Node, retNullable map[string]retNullability) []nullSource {
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
		if callee == "" || retNullable[callee] == retNotNull {
			return
		}
		src := nullSource{variable: name, line: rhs.StartLine(), origin: callee, definite: false}
		classifySynthArgs(rhs, &src)
		out = append(out, src)
	})
	return out
}

// classifySynthArgs records the call-site argument facts a
// conditional-nonnull-getter dismissal needs: identifier arguments (checked
// against the reaching analysis at the assignment line) and whether any
// argument is an opaque shape that cannot be proven non-null. An
// address-of argument (`&x`) and a string literal are always non-null; a
// parenthesized/cast wrapper is unwrapped; everything else (NULL literal,
// call result, arithmetic) marks the source unsafe to dismiss.
// synthArgKind classifies one call-site argument by its syntactic shape for
// the inter-procedural guard contracts: an identifier's nullability resolves
// against the reaching analysis, a string literal / address-of / sizeof /
// positive literal is provably non-null (and a sizeof or positive literal is
// additionally a positive length), and anything else (a NULL literal, a
// nested call, arithmetic) is opaque and keeps the source fail-open.
type synthArgKind uint8

const (
	argIdent synthArgKind = iota
	argStrLit
	argAddrOf
	argSizeof
	argPosLit
	argOther
)

// synthArgInfo is one argument's shape; name is set only for argIdent.
type synthArgInfo struct {
	name string
	kind synthArgKind
}

func classifySynthArgs(rhs parser.Node, src *nullSource) {
	if rhs.Kind() != "call_expression" {
		src.argUnsafe = true
		return
	}
	args := callArgs(rhs)
	if len(args) == 0 {
		src.argUnsafe = true
		return
	}
	for _, a := range args {
		info := synthArgInfo{kind: argOther}
		switch a.Kind() {
		case "identifier":
			if a.Text() == "NULL" {
				src.argUnsafe = true
				break
			}
			info.kind, info.name = argIdent, a.Text()
			src.argVarNames = append(src.argVarNames, a.Text())
		case "string_literal":
			info.kind = argStrLit
		case "parenthesized_expression", "cast_expression":
			kids := a.NamedChildren()
			if len(kids) == 1 && kids[0].Kind() == "identifier" && kids[0].Text() != "NULL" {
				info.kind, info.name = argIdent, kids[0].Text()
				src.argVarNames = append(src.argVarNames, kids[0].Text())
			} else {
				src.argUnsafe = true
			}
		case "unary_expression", "pointer_expression":
			if isAddressOfExpr(a) {
				info.kind = argAddrOf
			} else {
				src.argUnsafe = true
			}
		case "sizeof_expression":
			info.kind = argSizeof
		case "number_literal":
			if v, err := strconv.ParseInt(strings.TrimSpace(a.Text()), 0, 64); err == nil && v > 0 {
				info.kind = argPosLit
			} else {
				src.argUnsafe = true
			}
		default:
			src.argUnsafe = true
		}
		src.argInfo = append(src.argInfo, info)
	}
}

// isAddressOfExpr reports whether node is a unary address-of expression
// (`&x`, `&s->f`, `&arr[i]`) — a value that can never be null. tree-sitter-c
// parses both `*p` and `&x` as pointer_expression, distinguished by the
// operator token.
func isAddressOfExpr(n parser.Node) bool {
	switch n.Kind() {
	case "unary_expression", "pointer_expression":
	default:
		return false
	}
	for _, c := range n.Children() {
		if c.Kind() == "&" {
			return true
		}
	}
	return false
}

// retNullability grades HOW the pipeline knows a function can return a
// possibly-null pointer: proven (a concrete witness — a literal NULL return,
// an allocator, a known maybe-null libc API, or a callee already graded
// proven), assumed (a fail-open assumption — a pointer parameter, a field
// read, an unknown external call, an unrecognized expression), or notNull.
// Only proven may auto-confirm: an assumed source stays suspected for the AI
// so an analyzer limitation is never presented to the classifier as a
// machine proof.
type retNullability uint8

const (
	retNotNull retNullability = iota
	retNullAssumed
	retNullProven
)

// returnsNullability grades body's return-nullability: the strongest grade
// over all return expressions (proven > assumed > notNull). fnRetType is the
// enclosing function's declared return type: a bare integer zero (or a bare
// NULL identifier) in a never-null scalar return function is the integer
// zero, not a null pointer — the return-type gate.
// collectNoreturnCalls returns the set of call-target names that never return:
// the standard noreturn functions (abort/exit/...), in-scan functions whose body
// has no return statement and calls a noreturn target (transitive), and global
// function-pointer variables initialized to a noreturn function
// (`static void (*X)(size_t) = zmalloc_default_oom;`). This is how
// `if (!p) zmalloc_oom_handler(size)` (a pointer to a function that aborts)
// earns "the null path dies here" without a config entry — resolved from the
// scan tree itself.
func collectNoreturnCalls(cache *fileParseCache, funcs []*db.Function, fileByID map[int64]*db.File) map[string]bool {
	noreturn := make(map[string]bool, len(apikb.NoReturnCalls))
	for name := range apikb.NoReturnCalls {
		noreturn[name] = true
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range funcs {
			if noreturn[fn.Name] {
				continue
			}
			file := fileByID[fn.FileID]
			if file == nil {
				continue
			}
			body, root := cache.get(file, fn)
			if body.Kind() == "compound_statement" {
				// A function with no return statement that calls a noreturn
				// target never returns (its only exits are noreturn calls).
				if len(body.FindAll("return_statement")) == 0 {
					for _, call := range body.FindAll("call_expression") {
						if noreturn[callName(call)] {
							noreturn[fn.Name] = true
							changed = true
							break
						}
					}
				}
			}
			// Function-pointer globals: `static void (*X)(...) = Y;` where Y is
			// noreturn makes X() noreturn.
			if root.Kind() != "" {
				for _, decl := range root.FindAll("declaration") {
					for _, init := range decl.FindAll("init_declarator") {
						lhs := init.ChildByFieldName("declarator")
						rhs := init.ChildByFieldName("value")
						if lhs == nil || rhs == nil || rhs.Kind() != "identifier" {
							continue
						}
						name := functionPointerVarName(lhs.Text())
						if name == "" || noreturn[name] {
							continue
						}
						if noreturn[rhs.Text()] {
							noreturn[name] = true
							changed = true
						}
					}
				}
			}
		}
	}
	return noreturn
}

// functionPointerVarName pulls the variable name out of a function-pointer
// declarator text `(*zmalloc_oom_handler)(size_t)` → "zmalloc_oom_handler".
// A non-function-pointer declarator returns "".
func functionPointerVarName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 3 || s[0] != '(' || s[1] != '*' {
		return ""
	}
	s = s[2:]
	for i, c := range s {
		if c == ')' {
			return strings.TrimSpace(s[:i])
		}
	}
	return ""
}

// abortGuardVar returns the variable an `if (!v) <noreturn-call>` guard protects:
// the consequence calls a never-returning target, so the null path dies there
// and the fall-through (and any later `return v`) is non-null.
func abortGuardVar(ifStmt parser.Node, noreturnCalls map[string]bool) string {
	cond := ifStmt.ChildByFieldName("condition")
	if cond == nil {
		return ""
	}
	vars := parser.NullCheckedVars(*cond)
	if len(vars) == 0 {
		return ""
	}
	cons := ifStmt.ChildByFieldName("consequence")
	if cons == nil || !callsNoreturn(*cons, noreturnCalls) {
		return ""
	}
	return vars[0]
}

// callsNoreturn reports whether node (a guard consequence) contains a call to a
// never-returning target.
func callsNoreturn(node parser.Node, noreturnCalls map[string]bool) bool {
	for _, call := range node.FindAll("call_expression") {
		if noreturnCalls[callName(call)] {
			return true
		}
	}
	return false
}

// isAbortGuardedReturn reports whether a return expression is a bare identifier
// (or a cast/paren of one) that an `if (!v) <noreturn>` guard protects.
func isAbortGuardedReturn(expr parser.Node, abortGuarded map[string]bool) bool {
	inner := expr
	for inner.Kind() == "cast_expression" || inner.Kind() == "parenthesized_expression" {
		kids := inner.NamedChildren()
		var next parser.Node
		for _, k := range kids {
			if k.Kind() == "type_descriptor" {
				continue
			}
			next = k
			break
		}
		if next.Kind() == "" {
			break
		}
		inner = next
	}
	return inner.Kind() == "identifier" && abortGuarded[inner.Text()]
}

func returnsNullability(body parser.Node, flow *flowResult, params map[string]int, retNullable map[string]retNullability, analyzed map[string]bool, arrs *arrayBaseInfo, srcs []nullSource, fnRetType string, noreturnCalls map[string]bool) retNullability {
	// abort-on-OOM contract: a returned variable guarded by `if (!v) <noreturn>`
	// is non-null at the return — the null path dies in the never-returning
	// call. This is the scan-tree resolution of the same contract
	// config [nullability.non_null_returns] declares by name (xmalloc, zmalloc,
	// ...): a wrapper `p = alloc(); if (!p) abort(); return p;` never returns
	// NULL, so a deref of its result is not a null-deref.
	abortGuarded := map[string]bool{}
	for _, ifStmt := range body.FindAll("if_statement") {
		if v := abortGuardVar(ifStmt, noreturnCalls); v != "" {
			abortGuarded[v] = true
		}
	}
	grade := retNotNull
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		if isAbortGuardedReturn(children[0], abortGuarded) {
			continue
		}
		switch exprRetNullability(children[0], flow, params, retNullable, analyzed, arrs, ret.StartLine(), srcs, fnRetType) {
		case retNullProven:
			return retNullProven
		case retNullAssumed:
			grade = retNullAssumed
		}
	}
	return grade
}

func exprRetNullability(expr parser.Node, flow *flowResult, params map[string]int, retNullable map[string]retNullability, analyzed map[string]bool, arrs *arrayBaseInfo, line int, srcs []nullSource, fnRetType string) retNullability {
	if isNullLiteralNode(expr) {
		// Return-type gate: a bare zero/NULL literal in a never-null scalar
		// return function is the integer zero, not a null pointer. A
		// pointer-cast zero (`(T *)0`) keeps its null literal meaning
		// regardless of the function's declared return type.
		if apikb.IsNeverNullScalarType(fnRetType) && expr.Kind() != "cast_expression" {
			return retNotNull
		}
		return retNullProven
	}
	switch expr.Kind() {
	case "number_literal", "char_literal", "string_literal", "true", "false", "sizeof_expression":
		// Non-pointer scalars and string literals (static storage) are non-null.
		return retNotNull
	case "pointer_expression":
		// `&x` is an address (always non-null); `*p` is a deref whose pointed-to
		// value is unknown — an assumption, not a proof.
		if strings.HasPrefix(strings.TrimSpace(expr.Text()), "&") {
			return retNotNull
		}
		return retNullAssumed
	case "identifier":
		if _, isParam := params[expr.Text()]; isParam {
			return retNullAssumed
		}
		if flow != nil && flow.reaching(expr.Text(), line) {
			if variableRetStrength(srcs, expr.Text(), line, retNullable) {
				return retNullProven
			}
			return retNullAssumed
		}
		return retNotNull
	case "cast_expression", "parenthesized_expression":
		grade := retNotNull
		for _, c := range expr.NamedChildren() {
			// A cast's type_descriptor child names the TARGET TYPE, not a
			// value — recursing into it hits the fail-open default and
			// downgrades the whole cast to assumed even when the operand is a
			// provably non-null static-array base (`(T *)(g_arr + i * 8)`).
			if c.Kind() == "type_descriptor" {
				continue
			}
			// Inside a cast the operand's null-ness is fixed by the cast, not
			// the function's return type; a parenthesized wrapper preserves it.
			inner := fnRetType
			if expr.Kind() == "cast_expression" {
				inner = ""
			}
			switch exprRetNullability(c, flow, params, retNullable, analyzed, arrs, line, srcs, inner) {
			case retNullProven:
				return retNullProven
			case retNullAssumed:
				grade = retNullAssumed
			}
		}
		return grade
	case "binary_expression":
		// Pointer arithmetic on a static base (`return g_pool_var.sects + id`,
		// `return arr - 1`): the result is an address inside or one past the
		// array and can never be NULL. Only + and - are pointer arithmetic;
		// every other binary operator yields an integer, which the fail-open
		// default below keeps conservatively nullable.
		if op := parser.BinaryOperator(expr); op == "+" || op == "-" {
			children := expr.NamedChildren()
			if len(children) == 2 && (isNonNullArrayBase(children[0], arrs) || isNonNullArrayBase(children[1], arrs)) {
				return retNotNull
			}
		}
	case "call_expression":
		name := callName(expr)
		// A function the fixpoint actually analyzed resolves via its body
		// analysis (abort-on-OOM wrappers, transitive nullability) — NOT the
		// "contains malloc" name heuristic (xmalloc is an abort-on-OOM wrapper
		// that heuristic would grade nullable). `analyzed` is the caller-closure
		// (`needNames`); an in-scan function NOT in the closure falls through to
		// the fail-open default, same as an external one — never an unsound
		// "non-null because unanalyzed".
		if analyzed[name] {
			return retNullable[name]
		}
		if apikb.IsNonNullReturning(name) {
			return retNotNull
		}
		if isAllocatorCall(name) {
			return retNullProven
		}
		if apikb.IsKnownNullableReturn(name) {
			return retNullProven
		}
		return retNullAssumed // external/unknown callee: fail-open (open world)
	}
	// field_expression (e.g. `return g_space.shell_conf`, NULL-initialized),
	// subscript_expression, conditional/binary/unary — all may yield a pointer
	// and therefore may be NULL, but without a concrete witness this is an
	// assumption (fail-open), never a proof.
	return retNullAssumed
}

// variableRetStrength reports whether every null source for variable that can
// reach line is a proven-nullable origin: an explicit NULL assignment
// (definite), a declared allocator, a known maybe-null libc function, or a
// call result of a callee the fixpoint graded proven. Any other origin (an
// external_call, a caller_null, an assumed callee) downgrades to assumed —
// the conservative direction: the candidate stays suspected for the AI instead
// of auto-confirming on incomplete evidence. Only the sources on the LAST
// source line at or before line are considered, matching single-variable
// sequential reassignment; an unpositioned source cannot be ordered and is
// treated as assumed.
func variableRetStrength(srcs []nullSource, variable string, line int, retNullable map[string]retNullability) bool {
	best := 0
	var at []nullSource
	for _, s := range srcs {
		if s.variable != variable {
			continue
		}
		if s.line <= 0 {
			return false // unpositioned source: cannot grade, fail open
		}
		if s.line > line {
			continue
		}
		if s.line > best {
			best = s.line
			at = at[:0]
		}
		if s.line == best {
			at = append(at, s)
		}
	}
	if len(at) == 0 {
		return false
	}
	for _, s := range at {
		switch {
		case s.definite:
			// `p = NULL` — a concrete witness.
		case apikb.IsDeclaredAllocator(s.origin) || apikb.IsKnownNullableReturn(s.origin):
			// malloc/strchr/... — inherently maybe-null by contract.
		case s.origin != "" && retNullable[s.origin] == retNullProven:
			// Planner-synthesized `p = f()` source whose callee the fixpoint
			// graded proven.
		default:
			return false
		}
	}
	return true
}

// arrayBaseInfo is the static-array knowledge that lets exprReturnsNullable
// recognize pointer arithmetic on a static array base
// (`return g_pool_var.sects + id`) as non-null: an array lives at a fixed
// address, so base ± any offset yields an address inside (or one past) the
// array and can never be NULL.
type arrayBaseInfo struct {
	arrays      map[string]bool
	arrayFields map[string]bool
	// facts is the tree-wide fallback: an array or an array-typed field declared
	// in a header (the normal C layout) is invisible to the per-file scan above,
	// and treating it as a pointer would manufacture a null-deref candidate for
	// `hdr_array[i]`.
	facts *repofacts.Facts
}

func (a *arrayBaseInfo) isArray(name string) bool {
	if a == nil {
		return false
	}
	if a.arrays[name] {
		return true
	}
	_, ok := a.facts.GlobalArray(name)
	return ok
}

func (a *arrayBaseInfo) isArrayField(name string) bool {
	if a == nil {
		return false
	}
	if a.arrayFields[name] {
		return true
	}
	ff, ok := a.facts.FieldByName(name)
	return ok && ff.Array
}

// collectArrayBaseInfo gathers, for one function, the names that provably
// denote static arrays: array declarators at file scope (globals, including
// extern ones) or inside the function's own body, minus the function's
// parameters (an array parameter is really a caller-controlled pointer), plus
// struct field names whose visible declarations are arrays. A field name also
// declared as a non-array is dropped: the name alone does not identify the
// struct, so an ambiguous name stays fail-open (the same ambiguity guard
// findFieldTypeName uses).
func collectArrayBaseInfo(root, body parser.Node, params map[string]int, facts *repofacts.Facts) *arrayBaseInfo {
	info := &arrayBaseInfo{arrays: make(map[string]bool), arrayFields: make(map[string]bool), facts: facts}
	if root.Kind() == "" {
		return info
	}
	for _, decl := range root.FindAll("declaration") {
		// Other functions' locals must not leak their array names into this
		// function; file-scope declarations and the function's own locals are kept.
		if !nodeInsideTree(decl, body) && nodeInsideFunction(decl) {
			continue
		}
		for _, ad := range decl.FindAll("array_declarator") {
			if name := arrayBaseDeclaratorName(ad); name != "" {
				info.arrays[name] = true
			}
		}
	}
	for name := range params {
		delete(info.arrays, name)
	}
	nonArrayFields := make(map[string]bool)
	for _, fd := range root.FindAll("field_declaration") {
		ads := fd.FindAll("array_declarator")
		for _, ad := range ads {
			if name := arrayBaseDeclaratorName(ad); name != "" {
				info.arrayFields[name] = true
			}
		}
		if len(ads) == 0 {
			for _, fi := range fd.FindAll("field_identifier") {
				nonArrayFields[fi.Text()] = true
			}
		}
	}
	for name := range nonArrayFields {
		delete(info.arrayFields, name)
	}
	return info
}

// arrayBaseDeclaratorName returns the declared name of an array declarator,
// covering both plain identifiers and struct field identifiers (which
// declaratorName does not resolve).
func arrayBaseDeclaratorName(n parser.Node) string {
	switch n.Kind() {
	case "identifier", "field_identifier":
		return n.Text()
	case "pointer_declarator", "array_declarator", "function_declarator":
		for _, c := range n.NamedChildren() {
			if name := arrayBaseDeclaratorName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

// isNonNullArrayBase reports whether expr is a pointer expression whose value
// is a static address: a file/function-scoped array name, a struct field that
// is an array, an address-of, or a string literal. Such a base plus or minus
// any offset stays at or past the array — never NULL.
func isNonNullArrayBase(expr parser.Node, arrs *arrayBaseInfo) bool {
	switch expr.Kind() {
	case "identifier":
		return arrs.isArray(expr.Text())
	case "field_expression":
		for _, c := range expr.NamedChildren() {
			if c.Kind() == "field_identifier" {
				return arrs.isArrayField(c.Text())
			}
		}
		return false
	case "pointer_expression":
		return strings.HasPrefix(strings.TrimSpace(expr.Text()), "&")
	case "string_literal":
		return true
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if isNonNullArrayBase(c, arrs) {
				return true
			}
		}
		return false
	}
	return false
}

// nodeInsideTree reports whether node lies within the subtree rooted at tree.
// The walk follows node's parent chain and compares byte ranges, so a match is
// always a node on the same tree.
func nodeInsideTree(node, tree parser.Node) bool {
	if tree.Kind() == "" || node.Kind() == "" {
		return false
	}
	for p := node.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == tree.Kind() && p.StartByte() == tree.StartByte() && p.EndByte() == tree.EndByte() {
			return true
		}
	}
	return false
}

// nodeInsideFunction reports whether node sits inside any function definition,
// i.e. it is function-local rather than file-scope.
func nodeInsideFunction(node parser.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "function_definition" {
			return true
		}
	}
	return false
}

func isNullLiteralExpr(text string) bool {
	t := strings.TrimSpace(text)
	for len(t) >= 2 && t[0] == '(' && t[len(t)-1] == ')' && nullLiteralParensBalanced(t[1:len(t)-1]) {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	switch t {
	case "NULL", "nullptr", "(void*)0", "(void *)0", "((void*)0)", "((void *)0)":
		return true
	}
	return false
}

// isNullLiteralNode is the node-precise form of isNullLiteralExpr. It also
// recognizes a pointer-typed cast of a null constant (`p = (T*)NULL`,
// `p = (T*)0`), which the text matcher missed and which therefore left the
// assignment as a kill instead of a definite null source.
func isNullLiteralNode(expr parser.Node) bool {
	switch expr.Kind() {
	case "parenthesized_expression":
		children := expr.NamedChildren()
		if len(children) == 0 {
			return false
		}
		return isNullLiteralNode(children[0])
	case "cast_expression":
		var operand parser.Node
		isPointerCast := false
		for _, child := range expr.NamedChildren() {
			if child.Kind() == "type_descriptor" {
				if strings.Contains(child.Text(), "*") {
					isPointerCast = true
				}
				continue
			}
			operand = child
		}
		if !isPointerCast || operand.Kind() == "" {
			return false
		}
		return isNullLiteralNode(operand)
	case "identifier":
		t := strings.TrimSpace(expr.Text())
		return t == "NULL" || t == "nullptr"
	case "null":
		return true
	case "number_literal":
		return strings.TrimSpace(expr.Text()) == "0"
	}
	return false
}

// nullLiteralParensBalanced reports whether s has balanced parentheses, so a
// parenthesized null literal (`(NULL)`) is stripped while a non-literal
// expression is left untouched.
func nullLiteralParensBalanced(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
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
		if isNullLiteralNode(expr) {
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

func isAllocatorCall(name string) bool { return apikb.IsAllocator(name) }

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
