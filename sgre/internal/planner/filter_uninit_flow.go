package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// DefiniteInitFilter converges the uninit (VALUE_USE) candidate stream with the
// same flow-sensitive graph engine as null-deref. A stack_uninit candidate is
// dropped when the variable is *definitely initialized* on every path to the
// use — i.e. the declaration's uninitialized source no longer reaches the use
// because an assignment (full `v = ...`, or a field/subscript write that starts
// initializing a struct/array) sits on every path. This is the planner-side
// analogue of the detector's crude scope heuristic, but on the real statement
// CFG + DATA_FLOW instead of line/scope ranges.
//
// It is deliberately scoped to the stack_uninit origin: struct_partial_uninit
// and heap_uninit have field/pointer granularity and different kill semantics,
// so they are left for the detector + ranking.
type DefiniteInitFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDefiniteInitFilter(store db.Store, p *parser.Parser, logger *log.Logger) *DefiniteInitFilter {
	return &DefiniteInitFilter{store: store, parser: p, logger: logger}
}

func (f *DefiniteInitFilter) Name() string { return "definite_init" }

func (f *DefiniteInitFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}

	flows, roots := f.buildFlows(ctx, byFunc)

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		flow := flows[c.FunctionID]
		if flow == nil {
			kept = append(kept, c)
			continue
		}
		if !f.isStackUninit(ctx, c) {
			kept = append(kept, c)
			continue
		}
		// A use under a preprocessor conditional is covered by an assignment
		// under the SAME (or a subset of the) condition(s): the assignment
		// happens whenever the use is compiled, so the uninitialized source
		// reaching the use only via the "not compiled" branch is an
		// inconsistent path (e.g. crc32.c's `#if N > 1 crc1 = 0` ... `#if N > 1
		// word1 = crc1 ^ ...`).
		if flow.reaching(c.VariableName, c.Line) && f.hasCoveringAssign(ctx, roots[c.FunctionID], c) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("variable %s is assigned under the same preprocessor condition before the use at line %d", c.VariableName, c.Line))
			continue
		}
		if flow.reaching(c.VariableName, c.Line) {
			// The uninitialized declaration provably reaches the use: the graph
			// confirms a genuine uninitialized-variable read.
			c.SuspicionLevel = "confirmed"
			kept = append(kept, c)
		} else {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("variable %s is definitely initialized before the use at line %d", c.VariableName, c.Line))
		}
	}
	return kept, dropped, nil
}

// isStackUninit reports whether the candidate's VALUE_USE event is a
// stack_uninit candidate (the origin the flow filter understands).
func (f *DefiniteInitFilter) isStackUninit(ctx context.Context, c Candidate) bool {
	event, err := f.store.GetEventByID(ctx, c.DerefEventID)
	if err != nil || event == nil {
		return false
	}
	var props struct {
		Origin string `json:"origin"`
	}
	json.Unmarshal([]byte(event.Properties), &props)
	return props.Origin == "stack_uninit"
}

func (f *DefiniteInitFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate) (map[int64]*flowResult, map[int64]parser.Node) {
	flows := make(map[int64]*flowResult, len(byFunc))
	roots := make(map[int64]parser.Node, len(byFunc))
	for fid := range byFunc {
		fn, err := f.store.GetFunctionByID(ctx, fid)
		if err != nil || fn == nil {
			continue
		}
		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			continue
		}
		body, root := readFunctionBody(f.parser, fn, file)
		if body.Kind() != "compound_statement" {
			continue
		}
		flows[fid] = buildDefiniteInitFlow(fn, body, root)
		roots[fid] = root
	}
	return flows, roots
}

// buildDefiniteInitFlow runs the reaching-sources dataflow for uninitialized
// stack variables: gen = a local declaration without initializer, kill = any
// subsequent write to the variable (full or field/subscript), copy = `v = w`.
func buildDefiniteInitFlow(fn *db.Function, body parser.Node, root parser.Node) *flowResult {
	cfg := graph.BuildStmtCFG(body, fn.EndLine)

	// Effects are computed per CFG node from that node's OWN statement — never
	// from a line-keyed map. Line-keyed maps collide when several statements
	// share one line (`while (c) { x = n; n--; }` puts the while header, x=n
	// and n-- on the same line), which wrongly applied the body's copy/kill to
	// the while header and dropped a genuine loop-skip uninitialized use.
	effects := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		e := &nodeEffects{gen: map[string]bool{}, kill: map[string]bool{}, copy: map[string]string{}}

		// gen: an uninitialized local declaration (this node is the declaration).
		if n.Stmt.Kind() == "declaration" && isUninitDecl(n.Stmt) {
			for _, name := range declaredNames(n.Stmt) {
				e.gen[name] = true
			}
		}

		// kill/copy: only assignments that are direct children of this node's
		// statement (not assignments nested inside a branch/loop body, which
		// belong to their own CFG nodes).
		for _, p := range directAssignments(n.Stmt) {
			if p.lhs.Kind() == "identifier" {
				v := p.lhs.Text()
				if rv := rhsVarName(p.rhs); rv != "" {
					e.copy[v] = rv
				} else {
					e.kill[v] = true
				}
				continue
			}
			// field/subscript write initializes the base struct/array (field
			// granularity belongs to struct_partial_uninit).
			if base := assignBaseName(p.lhs); base != "" {
				e.kill[base] = true
			}
		}
		effects[n.ID] = e
	}

	nodeIn := runDataflow(cfg, effects)
	return &flowResult{cfg: cfg, nodeIn: nodeIn, genAt: genAt(cfg, effects)}
}

// assignPair is one (lhs, rhs) of an assignment/initializer that is a DIRECT
// child of a statement node.
type assignPair struct {
	lhs parser.Node
	rhs parser.Node
}

// directAssignments returns the (lhs, rhs) pairs of assignment_expression /
// init_declarator nodes that are DIRECT children of stmt, without recursing into
// nested statements. A while/if/for/switch header node must not inherit the
// assignments inside its body.
func directAssignments(stmt parser.Node) []assignPair {
	var pairs []assignPair
	switch stmt.Kind() {
	case "expression_statement":
		for _, child := range stmt.NamedChildren() {
			if child.Kind() != "assignment_expression" {
				continue
			}
			pairs = appendChainedAssign(pairs, child)
		}
	case "declaration":
		for _, child := range stmt.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			c := child.NamedChildren()
			if len(c) >= 2 {
				pairs = append(pairs, assignPair{lhs: c[0], rhs: c[1]})
			}
		}
	}
	return pairs
}

// appendChainedAssign flattens a (possibly chained) assignment expression into
// one (lhs, value) pair per assignment target. In `a = b = c = v` every target
// a, b, c ends up holding v's value, so each is paired with the innermost RHS v.
// The previous version only paired the outermost target with its immediate RHS
// (`a` with `b = c = v`), so the inner targets b and c were never marked
// initialized — which kept `int first; ... code = first = index = 0;` flagged as
// an uninitialized read of first/index.
func appendChainedAssign(pairs []assignPair, assign parser.Node) []assignPair {
	var targets []parser.Node
	cur := assign
	for cur.Kind() == "assignment_expression" {
		c := cur.NamedChildren()
		if len(c) < 2 {
			break
		}
		targets = append(targets, c[0])
		cur = c[1]
	}
	for _, lhs := range targets {
		pairs = append(pairs, assignPair{lhs: lhs, rhs: cur})
	}
	return pairs
}

// isUninitDecl reports whether a declaration declares variables without an
// initializer and without static storage (so they are born uninitialized).
func isUninitDecl(decl parser.Node) bool {
	hasInit := false
	isStatic := false
	for _, child := range decl.NamedChildren() {
		if child.Kind() == "init_declarator" {
			hasInit = true
		}
		if child.Kind() == "storage_class_specifier" && child.Text() == "static" {
			isStatic = true
		}
	}
	return !hasInit && !isStatic
}

// declaredNames returns the variable names a declaration introduces, skipping
// type/storage nodes and unwrapping declarators.
func declaredNames(decl parser.Node) []string {
	seen := make(map[string]bool)
	var names []string
	for _, child := range decl.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "type_identifier", "sized_type_specifier",
			"storage_class_specifier", "type_qualifier", "struct_specifier",
			"enum_specifier", "union_specifier", "init_declarator":
			continue
		}
		if name := declaratorName(child); name != "" && !seen[name] && !parser.IsCTypeKeyword(name) {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// assignBaseName returns the base variable an assignment writes to: a plain
// identifier, or the base identifier of a field/subscript access (so
// `stream.zalloc = ...` counts as initializing `stream` for stack_uninit).
func assignBaseName(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier", "field_expression", "subscript_expression",
		"pointer_declarator", "array_declarator", "function_declarator":
		return declaratorName(lhs)
	}
	return ""
}

// hasCoveringAssign reports whether c.VariableName has an assignment before
// c.Line whose compile-time (preprocessor) conditions AND runtime control-flow
// scopes are both subsets of the use's. Such an assignment happens on every
// compilation that also compiles the use, and on every runtime path that
// reaches the use, so the use cannot read an uninitialized value on any
// consistent compilation (the "not compiled" branch that the CFG models as a
// runtime alternative is inconsistent with the use's own condition).
func (f *DefiniteInitFilter) hasCoveringAssign(ctx context.Context, root parser.Node, c Candidate) bool {
	fn, err := f.store.GetFunctionByID(ctx, c.FunctionID)
	if err != nil || fn == nil {
		return false
	}
	usePreproc := preprocConditionKeys(root, fn, c.Line)
	if len(usePreproc) == 0 {
		return false
	}
	useRuntime := runtimeScopeKeys(root, fn, c.Line)
	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < fn.StartLine || assign.StartLine() > fn.EndLine {
			continue
		}
		if assign.StartLine() >= c.Line {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 1 {
			continue
		}
		if assignBaseName(children[0]) != c.VariableName {
			continue
		}
		assignPreproc := preprocConditionKeys(root, fn, assign.StartLine())
		if len(assignPreproc) == 0 || !isSubset(assignPreproc, usePreproc) {
			continue
		}
		assignRuntime := runtimeScopeKeys(root, fn, assign.StartLine())
		if isSubset(assignRuntime, useRuntime) {
			return true
		}
	}
	return false
}

// runtimeScopeKeys returns the normalized keys of every runtime conditional
// (if/while/for/do/switch) that contains line within fn.
func runtimeScopeKeys(root parser.Node, fn *db.Function, line int) []string {
	var keys []string
	for _, kind := range []string{"if_statement", "while_statement", "for_statement", "do_statement", "switch_statement"} {
		for _, stmt := range root.FindAll(kind) {
			if stmt.StartLine() < fn.StartLine || stmt.StartLine() > fn.EndLine {
				continue
			}
			if line < stmt.StartLine() || line > stmt.EndLine() {
				continue
			}
			keys = append(keys, fmt.Sprintf("%s@%d", kind, stmt.StartLine()))
		}
	}
	sort.Strings(keys)
	return keys
}

// preprocConditionKeys returns the normalized condition keys of every
// #ifdef/#ifndef/#if region that contains line within fn.
func preprocConditionKeys(root parser.Node, fn *db.Function, line int) []string {
	var keys []string
	for _, kind := range []string{"preproc_ifdef", "preproc_ifndef", "preproc_if"} {
		for _, pp := range root.FindAll(kind) {
			if pp.StartLine() < fn.StartLine || pp.StartLine() > fn.EndLine {
				continue
			}
			if line < pp.StartLine() || line > pp.EndLine() {
				continue
			}
			keys = append(keys, preprocKey(kind, pp))
		}
	}
	sort.Strings(keys)
	return keys
}

// preprocKey returns a normalized, comparable key for a preprocessor
// conditional: the directive kind plus the (whitespace-collapsed) condition.
func preprocKey(kind string, pp parser.Node) string {
	cond := ""
	if children := pp.NamedChildren(); len(children) > 0 {
		cond = collapseSpaces(children[0].Text())
	}
	switch kind {
	case "preproc_ifdef":
		return "ifdef " + cond
	case "preproc_ifndef":
		return "ifndef " + cond
	case "preproc_if":
		return "if " + cond
	}
	return kind
}

func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// isSubset reports whether every key in a also appears in b.
func isSubset(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, k := range b {
		set[k] = true
	}
	for _, k := range a {
		if !set[k] {
			return false
		}
	}
	return true
}
