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
	"github.com/DannyAn/secguard-clang/internal/macros"
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

	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	flows, files := f.buildFlows(ctx, byFunc, fnByID, fileByID)

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
		reaching := flow.reaching(c.VariableName, c.Line)
		if reaching && f.hasCoveringAssign(ctx, fnByID, files[c.FileID], c) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("variable %s is assigned under the same preprocessor condition before the use at line %d", c.VariableName, c.Line))
			continue
		}
		if reaching {
			// The uninitialized declaration reaches the use. It is a CERTAIN
			// uninitialized read only when it reaches on every path (must);
			// otherwise it stays a suspicion for the AI to confirm.
			if flow.mustReaching(c.VariableName, c.Line) {
				c.SuspicionLevel = "confirmed"
				// An output-param write (`&x` passed to a callee) is invisible to
				// the flow engine's gen/kill model (it only tracks direct
				// assignments, field writes, and macro outputs), so "uninit on
				// every path" is unproven when such a write precedes the use —
				// the callee may have written x on the success path. Downgrade to
				// suspected so the AI weighs the interprocedural write instead of
				// rubber-stamping a machine-confirmed false positive.
				if f.hasOutputParamWrite(fnByID, files[c.FileID], c) {
					c.SuspicionLevel = "suspected"
				}
			}
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

func (f *DefiniteInitFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate, fnByID map[int64]*db.Function, fileByID map[int64]*db.File) (map[int64]*flowResult, map[int64]*hoistedUninitFile) {
	flows := make(map[int64]*flowResult, len(byFunc))
	files := make(map[int64]*hoistedUninitFile)
	macroWritesByFile := make(map[int64]map[string]macros.WriteSummary)
	cache := newFileParseCache(f.parser)
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
		macroWrites := macroWritesByFile[file.ID]
		if macroWrites == nil {
			macroWrites = macros.WriteSummaries(root)
			macroWritesByFile[file.ID] = macroWrites
		}
		flows[fid] = buildDefiniteInitFlow(fn, body, macroWrites)
		if _, ok := files[file.ID]; !ok {
			files[file.ID] = hoistUninitFile(root)
		}
	}
	return flows, files
}

// buildDefiniteInitFlow runs the reaching-sources dataflow for uninitialized
// stack variables: gen = a local declaration without initializer, kill = any
// subsequent write to the variable (full or field/subscript, plus a
// function-like macro output argument), copy = `v = w`.
func buildDefiniteInitFlow(fn *db.Function, body parser.Node, macroWrites map[string]macros.WriteSummary) *flowResult {
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

		// A function-like macro that writes one of its arguments (`#define
		// OUT(x) (x) = ...` → `OUT(v)`) initializes it at this node, so it is a
		// kill for the uninit source — the planner-side mirror of the detector's
		// output-parameter recording.
		for _, call := range n.Stmt.FindAll("call_expression") {
			for name := range macros.WrittenArgs(call, macroWrites) {
				e.kill[name] = true
			}
		}
		effects[n.ID] = e
	}

	nodeIn := runDataflow(cfg, effects, nil)
	res := &flowResult{cfg: cfg, nodeIn: nodeIn, genAt: genAt(cfg, effects)}
	res.must, res.mustGenAt = runMustDataflow(cfg, effects)
	return res
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
// assignments inside its body. A bare assignment_expression is handled because a
// for-initializer (`for (i = 0; ...)`) is parsed directly as an
// assignment_expression, not wrapped in an expression_statement.
func directAssignments(stmt parser.Node) []assignPair {
	var pairs []assignPair
	switch stmt.Kind() {
	case "assignment_expression":
		pairs = appendChainedAssign(pairs, stmt)
	case "expression_statement":
		for _, child := range stmt.NamedChildren() {
			if child.Kind() != "assignment_expression" {
				continue
			}
			pairs = appendChainedAssign(pairs, child)
		}
	case "comma_expression":
		// for-loop update clause (`pre = cur, cur = cur->next`): each
		// comma-separated assignment is its own transfer effect.
		for _, child := range stmt.NamedChildren() {
			if child.Kind() == "assignment_expression" {
				pairs = appendChainedAssign(pairs, child)
			}
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
	case "if_statement", "while_statement", "do_statement", "for_statement":
		// A control-flow header that assigns in its condition
		// (`while ((c = *str++))`, `if ((x = f()) == -1)`) writes the LHS every
		// time the header is evaluated — before any body statement — so the
		// header node is a direct assign site for the LHS. A for-loop's
		// initializer/update are their own CFG nodes, so only the condition is
		// extracted here (the header's Stmt wraps the whole statement).
		if cond := stmt.ChildByFieldName("condition"); cond != nil {
			for _, a := range cond.FindAll("assignment_expression") {
				pairs = appendChainedAssign(pairs, a)
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

// hoistedUninitFile holds the whole-file node lists the definite-init filter
// scans. They are collected once per file (hoistUninitFile) instead of once per
// candidate/function, which was the dominant remaining cost of the uninit
// filter (hasCoveringAssign issued ~9 whole-tree FindAll walks per candidate).
type hoistedUninitFile struct {
	assigns                                   []parser.Node
	calls                                     []parser.Node
	ifs, whiles, fors, dos, switches          []parser.Node
	preprocIfs, preprocIfdefs, preprocIfndefs []parser.Node
}

func hoistUninitFile(root parser.Node) *hoistedUninitFile {
	return &hoistedUninitFile{
		assigns:        root.FindAll("assignment_expression"),
		calls:          root.FindAll("call_expression"),
		ifs:            root.FindAll("if_statement"),
		whiles:         root.FindAll("while_statement"),
		fors:           root.FindAll("for_statement"),
		dos:            root.FindAll("do_statement"),
		switches:       root.FindAll("switch_statement"),
		preprocIfs:     root.FindAll("preproc_if"),
		preprocIfdefs:  root.FindAll("preproc_ifdef"),
		preprocIfndefs: root.FindAll("preproc_ifndef"),
	}
}

// hasOutputParamWrite reports whether c.VariableName is passed by address
// (`&x`) to a call before the use, within the candidate's function. Such a write
// is invisible to buildDefiniteInitFlow's gen/kill model, so it is used only to
// downgrade an otherwise-must-reachable uninit from `confirmed` to `suspected`.
func (f *DefiniteInitFilter) hasOutputParamWrite(fnByID map[int64]*db.Function, hf *hoistedUninitFile, c Candidate) bool {
	if hf == nil {
		return false
	}
	fn := fnByID[c.FunctionID]
	if fn == nil {
		return false
	}
	for _, call := range hf.calls {
		if call.StartLine() < fn.StartLine || call.StartLine() > fn.EndLine || call.StartLine() >= c.Line {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for _, arg := range child.NamedChildren() {
				if arg.Kind() != "pointer_expression" || !strings.HasPrefix(strings.TrimSpace(arg.Text()), "&") {
					continue
				}
				inner := arg.NamedChildren()
				if len(inner) == 0 || inner[0].Kind() != "identifier" {
					continue
				}
				if inner[0].Text() == c.VariableName {
					return true
				}
			}
		}
	}
	return false
}

// hasCoveringAssign reports whether c.VariableName has an assignment before
// c.Line whose compile-time (preprocessor) conditions AND runtime control-flow
// scopes are both subsets of the use's. Such an assignment happens on every
// compilation that also compiles the use, and on every runtime path that
// reaches the use, so the use cannot read an uninitialized value on any
// consistent compilation (the "not compiled" branch that the CFG models as a
// runtime alternative is inconsistent with the use's own condition).
func (f *DefiniteInitFilter) hasCoveringAssign(ctx context.Context, fnByID map[int64]*db.Function, hf *hoistedUninitFile, c Candidate) bool {
	if hf == nil {
		return false
	}
	fn := fnByID[c.FunctionID]
	if fn == nil {
		return false
	}
	usePreproc := preprocConditionKeys(hf, fn, c.Line)
	if len(usePreproc) == 0 {
		return false
	}
	useRuntime := runtimeScopeKeys(hf, fn, c.Line)
	for _, assign := range hf.assigns {
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
		assignPreproc := preprocConditionKeys(hf, fn, assign.StartLine())
		if len(assignPreproc) == 0 || !isSubset(assignPreproc, usePreproc) {
			continue
		}
		assignRuntime := runtimeScopeKeys(hf, fn, assign.StartLine())
		if isSubset(assignRuntime, useRuntime) {
			return true
		}
	}
	return false
}

// runtimeScopeKeys returns the normalized keys of every runtime conditional
// (if/while/for/do/switch) that contains line within fn.
func runtimeScopeKeys(hf *hoistedUninitFile, fn *db.Function, line int) []string {
	var keys []string
	for _, list := range [][]parser.Node{hf.ifs, hf.whiles, hf.fors, hf.dos, hf.switches} {
		for _, stmt := range list {
			if stmt.StartLine() < fn.StartLine || stmt.StartLine() > fn.EndLine {
				continue
			}
			if line < stmt.StartLine() || line > stmt.EndLine() {
				continue
			}
			keys = append(keys, fmt.Sprintf("%s@%d", stmt.Kind(), stmt.StartLine()))
		}
	}
	sort.Strings(keys)
	return keys
}

// preprocConditionKeys returns the normalized condition keys of every
// #ifdef/#ifndef/#if region that contains line within fn.
func preprocConditionKeys(hf *hoistedUninitFile, fn *db.Function, line int) []string {
	var keys []string
	for _, list := range [][]parser.Node{hf.preprocIfdefs, hf.preprocIfndefs, hf.preprocIfs} {
		for _, pp := range list {
			if pp.StartLine() < fn.StartLine || pp.StartLine() > fn.EndLine {
				continue
			}
			if line < pp.StartLine() || line > pp.EndLine() {
				continue
			}
			keys = append(keys, preprocKey(pp.Kind(), pp))
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
