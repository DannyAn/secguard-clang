package planner

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
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
	// arrayNames caches, per file, the set of identifiers declared as arrays
	// (array-to-pointer decay yields a non-null pointer).
	arrayNames map[int64]map[string]bool
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
	// definite is a second, separate dataflow seeded only with EXPLICIT null
	// assignments (`p = NULL`). A source reaching here means the pointer is
	// CERTAINLY null — a must-null result, distinct from the may-null `reaching`.
	definite *flowResult
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
// reaches the dereference with no intervening kill — i.e. the pointer is
// certainly null. This is the must-null tier the AI does not need to re-derive.
func (m *flowResult) reachingDefinite(variable string, line int) bool {
	if m == nil || m.definite == nil {
		return false
	}
	return m.definite.reaching(variable, line)
}

// reachingAtExit reports whether variable has a reaching source at the function
// exit, i.e. there is a path on which the source is not killed before the
// function returns. This is the leak condition: allocated but not released on
// at least one path.
func (m *flowResult) reachingAtExit(variable string) bool {
	if m == nil || m.cfg == nil {
		return false
	}
	return len(m.nodeIn[m.cfg.Exit][variable]) > 0
}

// nodeEffects are the gen/kill/copy transfer effects of a single CFG node.
type nodeEffects struct {
	gen  map[string]bool
	kill map[string]bool
	copy map[string]string
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
		res.definite = a.analyzeFlow(ctx, fn, body, fileRoot, definiteGenByLine, nil, false, true)
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
	arrays := a.arraysForFile(fn.FileID, fileRoot)
	dfgByLine := a.dfgCopies[fn.ID]

	effects := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		effects[n.ID] = a.collectNodeEffects(n, genByLine, killByLine, dfgByLine, arrays, nonNullKills, definiteKills)
	}

	nodeIn := runDataflow(cfg, effects)
	return &flowResult{cfg: cfg, nodeIn: nodeIn, genAt: genAt(cfg, effects)}
}

// collectNodeEffects extracts the transfer effects for a single statement node.
func (a *flowAnalyzer) collectNodeEffects(n *graph.StmtNode, genByLine, killByLine map[int][]string, dfgByLine map[int][]copyPair, arrays map[string]bool, nonNullKills, definiteKills bool) *nodeEffects {
	e := &nodeEffects{gen: map[string]bool{}, kill: map[string]bool{}, copy: map[string]string{}}

	// gen/kill: event sources recorded at this statement's line.
	for _, v := range genByLine[n.StartLine] {
		e.gen[v] = true
	}
	for _, v := range killByLine[n.StartLine] {
		e.kill[v] = true
	}
	// DFG copies from the stored graph at this line.
	for _, cp := range dfgByLine[n.StartLine] {
		e.copy[cp.lhs] = cp.rhs
	}
	// AST-level copies, and (optionally) definite non-null kills.
	forEachAssignment(n.Stmt, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" {
			return
		}
		if rv := rhsVarName(rhs); rv != "" {
			e.copy[name] = rv
		} else if nonNullKills && definitelyNonNull(rhs, arrays) {
			e.kill[name] = true
		} else if definiteKills {
			// Must-null flow: ANY reassignment other than a variable copy
			// (p = malloc(), p = f(), p = 5, ...) replaces the old value, so the
			// old DEFINITE-null source no longer holds — kill it.
			e.kill[name] = true
		}
	})

	return e
}

// runDataflow runs the forward null-source reaching analysis. IN[entry] is
// empty (no variable is known null at function entry, matching the event-based
// source model), joins are unions of source-ID sets, and the transfer applies
// copy, kill, then gen. The lattice is monotone (source sets only grow at
// joins; a kill replaces a variable's set with the empty set, which is a fixed
// set-difference under union), so iteration order does not affect the fixpoint.
func runDataflow(cfg *graph.StmtCFG, effects map[int]*nodeEffects) map[int]map[string]map[int]bool {
	nodeIn := make(map[int]map[string]map[int]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		nodeIn[i] = map[string]map[int]bool{}
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
	for v := range e.gen {
		if out[v] == nil {
			out[v] = map[int]bool{}
		}
		out[v][nodeID] = true
	}
	return out
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
	case "parenthesized_expression":
		for _, c := range rhs.NamedChildren() {
			if name := rhsVarName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

// definitelyNonNull reports whether expr is a provably non-null pointer value:
// an address-of (`&x`), a string literal, a compound literal, or an array name
// decaying to a pointer. A cast/parenthesis is unwrapped to its operand.
func definitelyNonNull(expr parser.Node, arrays map[string]bool) bool {
	switch expr.Kind() {
	case "string_literal":
		return true
	case "pointer_expression":
		return strings.HasPrefix(expr.Text(), "&")
	case "compound_literal_expression":
		return true
	case "cast_expression", "parenthesized_expression":
		for _, c := range expr.NamedChildren() {
			if definitelyNonNull(c, arrays) {
				return true
			}
		}
		return false
	case "identifier":
		return arrays[expr.Text()]
	}
	return false
}

// arraysForFile lazily computes the set of array-declared identifiers in a file.
func (a *flowAnalyzer) arraysForFile(fileID int64, root parser.Node) map[string]bool {
	if a.arrayNames == nil {
		a.arrayNames = make(map[int64]map[string]bool)
	}
	if m, ok := a.arrayNames[fileID]; ok {
		return m
	}
	m := make(map[string]bool)
	if root.Kind() != "" {
		for _, ad := range root.FindAll("array_declarator") {
			if name := declaratorName(ad); name != "" {
				m[name] = true
			}
		}
	}
	a.arrayNames[fileID] = m
	return m
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
