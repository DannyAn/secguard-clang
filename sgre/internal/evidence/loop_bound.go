package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// LoopBoundDetector is the lightweight Loop Bound & Iteration Analysis stage.
// It does NOT build a new CFG or a symbol-execution engine: it walks the
// tree-sitter AST (which the indexer already produced) and extracts, for each
// for/while/do loop, the loop variable, the ascending upper bound and that
// bound's origin. It then emits a LOOP_BOUND event only for the two high-signal
// shapes the AI judgment boundary can act on:
//
//   - unchecked_input_bound (CWE-606): the loop's upper bound is a function
//     parameter or a local assigned from an external-input source (recv/read/
//     fread/getenv/…), and no upper-bound guard/clamp dominates the loop. The
//     iteration count is therefore not statically bounded.
//   - bound_mul (CWE-834): the loop's upper bound is a `var * var` product —
//     an overflow-prone iteration-count computation (CWE-190 linkage) whose
//     wrap directly changes how many times the loop runs.
//
// Every shape is emitted as suspected, never auto-confirmed: a large or
// externally-controlled loop is not a defect by itself (issue #334 §5/§6).
// Constant-bounded loops (`for (i = 0; i < 100; i++)`) are extracted for the
// iteration-count fact but NEVER emitted — they are the negative cases.
type LoopBoundDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewLoopBoundDetector(store db.Store, p *parser.Parser, logger *log.Logger) *LoopBoundDetector {
	return &LoopBoundDetector{store: store, parser: p, logger: logger}
}

func (d *LoopBoundDetector) Name() string { return "loop_bound" }

// loopBoundInputSources are the return-value external-input calls whose result
// can become a loop upper bound: network/file reads, environment lookups, and
// single-character reads. A length sourced from one of these crosses the trust
// boundary the AI must judge (network vs trusted local fd).
var loopBoundInputSources = map[string]bool{
	"recv": true, "recvfrom": true, "recvmsg": true,
	"read": true, "pread": true, "fread": true,
	"readv": true, "preadv": true,
	"getenv": true, "getchar": true, "fgetc": true,
	"getline": true, "getdelim": true, "getcwd": true,
}

func (d *LoopBoundDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		loops := append(root.FindAll("for_statement"), root.FindAll("while_statement")...)
		loops = append(loops, root.FindAll("do_statement")...)
		if len(loops) == 0 {
			return
		}
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		allIfs := root.FindAll("if_statement")

		paramsByLine := make(map[int][]string)
		for _, fnNode := range root.FindAll("function_definition") {
			paramsByLine[fnNode.StartLine()] = findParamsInDefinition(fnNode)
		}

		for _, f := range funcs {
			params := make(map[string]bool)
			for _, p := range paramsByLine[f.StartLine] {
				params[p] = true
			}
			assigned := collectLoopAssignments(inits, assigns, f)
			taintVars := collectLoopBoundTaintVars(assigns, inits, f)
			bounds := AnalyzeBounds(IfsInFunc(allIfs, f.StartLine, f.EndLine), assignsInFunc(assigns, f.StartLine, f.EndLine))

			for _, loop := range loops {
				if !funcLineRange(f, loop.StartLine()) {
					continue
				}
				d.analyzeLoop(ctx, loop, f, file, params, assigned, taintVars, bounds, allIfs, assigns, &result)
			}
		}
	})
	return result, err
}

// loopInfo is one loop's extracted structure: the construct, the induction
// variable and the ascending upper bound of its condition.
type loopInfo struct {
	kind      string
	loopVar   string
	bound     string
	boundNode parser.Node
	condText  string
}

// analyzeLoop extracts one loop's bound and emits the matching LOOP_BOUND event
// when the bound is externally-controlled (CWE-606) or an overflow-prone
// product (CWE-834). Constant and local bounds are not emitted.
func (d *LoopBoundDetector) analyzeLoop(ctx context.Context, loop parser.Node, f *db.Function, file *db.File, params map[string]bool, assigned map[string]parser.Node, taintVars map[string]string, bounds *RangeFacts, allIfs, assigns []parser.Node, result *DetectResult) {
	info := extractLoopInfo(loop)
	if info.bound == "" {
		return
	}

	// Resolve a named bound through one level of assignment only when it is
	// still an unclassified local, so `count = n * m; for (i = 0; i < count;
	// i++)` is judged by the product and `count = 10` by the constant. A bound
	// already classified as param/taint/const/compound/call is left as-is — in
	// particular a tainted local must NOT be re-classified by its RHS call.
	effBound := info.bound
	effNode := info.boundNode
	effKind := classifyBoundNode(effNode, params, taintVars)
	if effKind == "local" {
		if node, ok := assigned[bareBoundName(effBound)]; ok {
			effBound = strings.TrimSpace(node.Text())
			effNode = node
			effKind = classifyBoundNode(node, params, taintVars)
		}
	}

	// An upper-bound guard or clamp dominates the loop → the iteration count is
	// bounded on the reaching path, so neither shape is a defect. The bare-name
	// guard check only applies to named bounds; a compound product is judged by
	// the AI (its overflow risk is inherent to the computation).
	boundName := bareBoundName(effBound)
	if boundName != "" && effKind != "compound" {
		if bounds.UpperBoundAt(boundName, loop.StartLine()) > 0 {
			return
		}
		if hasLoopBoundUpperGuard(allIfs, f, boundName, loop.StartLine()) {
			return
		}
		if loopBoundClampedBefore(assigns, f, boundName, loop.StartLine()) {
			return
		}
		if loopBoundClampedByIf(allIfs, f, boundName, loop.StartLine()) {
			return
		}
	}

	var category string
	switch effKind {
	case "param", "taint":
		category = "unchecked_input_bound"
	case "compound":
		if isMulBoundNode(effNode) {
			category = "bound_mul"
		}
	}
	if category == "" {
		return
	}

	props := map[string]string{
		"category":        category,
		"variable":        effBound,
		"expression":      info.condText,
		"loop_kind":       info.kind,
		"loop_var":        info.loopVar,
		"loop_bound":      effBound,
		"loop_bound_kind": effKind,
	}
	if effKind == "taint" {
		props["origin"] = taintVars[boundName]
	}
	if emitEvent(ctx, d.store, d.logger, "LOOP_BOUND", f.ID, &db.Location{FileID: file.ID, Line: loop.StartLine(), Column: loop.StartColumn()}, props) {
		result.EventsCreated++
	}
}

// extractLoopInfo returns the loop construct, the induction variable and the
// ascending upper bound of a for/while/do condition. A condition that is not an
// ascending relational comparison (`var < bound` / `var <= bound`) yields an
// empty bound — descending, equality and pointer-traversal loops are not
// countable iteration bounds and are left alone.
func extractLoopInfo(loop parser.Node) loopInfo {
	kind := loop.Kind()
	cond := loop.ChildByFieldName("condition")
	if cond == nil {
		return loopInfo{kind: kind}
	}
	c := stripCastParenNode(*cond)
	for c.Kind() == "parenthesized_expression" {
		kids := c.NamedChildren()
		if len(kids) == 0 {
			return loopInfo{kind: kind}
		}
		c = kids[0]
	}
	if c.Kind() != "binary_expression" {
		return loopInfo{kind: kind}
	}
	op := parser.BinaryOperator(c)
	if op != "<" && op != "<=" {
		return loopInfo{kind: kind}
	}
	named := c.NamedChildren()
	if len(named) != 2 {
		return loopInfo{kind: kind}
	}
	lhs := stripCastParenNode(named[0])
	if lhs.Kind() != "identifier" {
		return loopInfo{kind: kind}
	}
	return loopInfo{
		kind:      kind,
		loopVar:   lhs.Text(),
		bound:     strings.TrimSpace(named[1].Text()),
		boundNode: named[1],
		condText:  strings.TrimSpace(cond.Text()),
	}
}

// bareBoundName returns the bare identifier of a bound expression, or "" when
// the bound is a compound expression (`n * m`, `p->count`).
func bareBoundName(bound string) string {
	t := strings.TrimSpace(bound)
	if t == "" {
		return ""
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !isIdentByte(c) {
			return ""
		}
	}
	return t
}

// classifyBoundNode classifies an AST bound node into its origin kind: a
// literal is "const", a bare parameter "param", a tainted local "taint", any
// other bare identifier "local", a non-input call "call", and anything compound
// (a product, a field/subscript access) "compound".
func classifyBoundNode(n parser.Node, params map[string]bool, taintVars map[string]string) string {
	n = stripCastParenNode(n)
	for n.Kind() == "parenthesized_expression" {
		kids := n.NamedChildren()
		if len(kids) == 0 {
			return "compound"
		}
		n = kids[0]
	}
	switch n.Kind() {
	case "number_literal":
		return "const"
	case "identifier":
		if params[n.Text()] {
			return "param"
		}
		if _, ok := taintVars[n.Text()]; ok {
			return "taint"
		}
		return "local"
	case "call_expression":
		// A direct call bound (`for (i = 0; i < recv(...); i++)`) is not
		// classified as external — the assignment-based taint map below is the
		// only external-input signal, so a bare call stays "call" and is left
		// for the AI/other detectors.
		return "call"
	default:
		return "compound"
	}
}

// isMulBoundNode reports whether the bound node is a `*` product with at least
// two non-constant operands — the overflow-prone iteration-count computation
// (issue #334 §4.3). A pure-literal product is not flagged (it is a constant).
func isMulBoundNode(n parser.Node) bool {
	n = stripCastParenNode(n)
	for n.Kind() == "parenthesized_expression" {
		kids := n.NamedChildren()
		if len(kids) == 0 {
			return false
		}
		n = kids[0]
	}
	if n.Kind() != "binary_expression" || parser.BinaryOperator(n) != "*" {
		return false
	}
	varCount := 0
	var collect func(x parser.Node)
	collect = func(x parser.Node) {
		x = stripCastParenNode(x)
		for x.Kind() == "parenthesized_expression" {
			kids := x.NamedChildren()
			if len(kids) == 0 {
				return
			}
			x = kids[0]
		}
		switch x.Kind() {
		case "binary_expression":
			if parser.BinaryOperator(x) == "*" {
				for _, child := range x.NamedChildren() {
					collect(child)
				}
				return
			}
			varCount++
		case "number_literal", "sizeof_expression":
			return
		default:
			// identifier, field_expression, call_expression, subscript, ...
			varCount++
		}
	}
	collect(n)
	return varCount >= 2
}

// collectLoopAssignments builds a name -> value-expression map for a function
// (init_declarator and assignment_expression), so a named loop bound can be
// resolved to its defining expression. Only an unambiguous single assignment is
// kept; a second assignment leaves the name absent so the value is not guessed.
func collectLoopAssignments(inits, assigns []parser.Node, f *db.Function) map[string]parser.Node {
	out := make(map[string]parser.Node)
	consider := func(lhs, rhs parser.Node) {
		name := assignedVariable(lhs)
		if name == "" {
			return
		}
		if _, seen := out[name]; seen {
			delete(out, name)
			return
		}
		out[name] = rhs
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		lhs, rhs, ok := init.AssignParts()
		if ok {
			consider(lhs, rhs)
		}
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		if children[0].Kind() == "identifier" {
			consider(children[0], children[1])
		}
	}
	return out
}

// collectLoopBoundTaintVars returns the locals assigned once from an
// external-input return (recv/read/fread/getenv/…), keyed name -> "fn:line".
func collectLoopBoundTaintVars(assigns, inits []parser.Node, f *db.Function) map[string]string {
	out := map[string]string{}
	consider := func(lhs, rhs parser.Node, line int) {
		name := assignedVariable(lhs)
		if name == "" {
			return
		}
		call := rhs
		for call.Kind() == "parenthesized_expression" || call.Kind() == "cast_expression" {
			kids := call.NamedChildren()
			if len(kids) == 0 {
				return
			}
			call = kids[len(kids)-1]
		}
		if call.Kind() != "call_expression" {
			return
		}
		callee := extractCallName(call)
		if !loopBoundInputSources[callee] {
			return
		}
		out[name] = fmt.Sprintf("%s:%d", callee, line)
	}
	for _, a := range assigns {
		if !funcLineRange(f, a.StartLine()) {
			continue
		}
		named := a.NamedChildren()
		if len(named) < 2 {
			continue
		}
		consider(named[0], named[1], a.StartLine())
	}
	for _, i := range inits {
		if !funcLineRange(f, i.StartLine()) {
			continue
		}
		lhs, rhs, ok := i.AssignParts()
		if !ok {
			continue
		}
		consider(lhs, rhs, i.StartLine())
	}
	return out
}

// hasLoopBoundUpperGuard reports whether an early-return guard
// (`if (bound > MAX) return;`) establishes an upper bound on the fall-through
// before the loop — the "bound > MAX error branch" exemption.
func hasLoopBoundUpperGuard(ifs []parser.Node, f *db.Function, boundName string, loopLine int) bool {
	for _, ifStmt := range ifs {
		if !funcLineRange(f, ifStmt.StartLine()) || ifStmt.StartLine() >= loopLine {
			continue
		}
		cond := ifStmt.ChildByFieldName("condition")
		cons := ifStmt.ChildByFieldName("consequence")
		if cond == nil || cons == nil || !isExitStmt(*cons) {
			continue
		}
		c := stripCastParenNode(*cond)
		op := ""
		for _, ch := range c.Children() {
			switch ch.Kind() {
			case ">", ">=":
				op = ch.Kind()
			}
		}
		if op == "" {
			continue
		}
		named := c.NamedChildren()
		if len(named) != 2 {
			continue
		}
		if normalizeGuardText(named[0].Text()) == boundName {
			return true
		}
	}
	return false
}

// loopBoundClampedBefore reports whether the bound is clamped
// (`bound = min(bound, cap)`) before the loop — the truncation idiom, exempted.
func loopBoundClampedBefore(assigns []parser.Node, f *db.Function, boundName string, loopLine int) bool {
	for _, a := range assigns {
		if !funcLineRange(f, a.StartLine()) || a.StartLine() >= loopLine {
			continue
		}
		named := a.NamedChildren()
		if len(named) < 2 {
			continue
		}
		if assignedVariable(named[0]) != boundName {
			continue
		}
		if strings.Contains(named[1].Text(), "min(") || strings.Contains(named[1].Text(), "MIN(") {
			return true
		}
	}
	return false
}

// loopBoundClampedByIf reports whether a conditional-assignment clamp
// (`if (bound > MAX) { bound = MAX; }`) establishes an upper bound on the
// fall-through before the loop — the cap-to-max idiom, exempted. The guard
// condition names the bound and the consequence reassigns it a constant.
func loopBoundClampedByIf(ifs []parser.Node, f *db.Function, boundName string, loopLine int) bool {
	for _, ifStmt := range ifs {
		if !funcLineRange(f, ifStmt.StartLine()) || ifStmt.StartLine() >= loopLine {
			continue
		}
		cond := ifStmt.ChildByFieldName("condition")
		cons := ifStmt.ChildByFieldName("consequence")
		if cond == nil || cons == nil {
			continue
		}
		c := stripCastParenNode(*cond)
		op := ""
		for _, ch := range c.Children() {
			switch ch.Kind() {
			case ">", ">=":
				op = ch.Kind()
			}
		}
		if op == "" {
			continue
		}
		named := c.NamedChildren()
		if len(named) != 2 || normalizeGuardText(named[0].Text()) != boundName {
			continue
		}
		for _, assign := range cons.FindAll("assignment_expression") {
			a := assign.NamedChildren()
			if len(a) < 2 {
				continue
			}
			if assignedVariable(a[0]) != boundName {
				continue
			}
			if parseConstantIndex(strings.TrimSpace(a[1].Text())) >= 0 {
				return true
			}
		}
	}
	return false
}
