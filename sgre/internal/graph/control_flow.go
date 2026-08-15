package graph

import (
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// StmtNode is one node in a statement-level control-flow graph (CFG). A node
// either carries a real source statement (Kind == "stmt"), or is a synthetic
// entry/exit/join marker used to stitch branches and loops together.
//
// The CFG is built as an *over-approximation* of control flow: every real
// execution path is represented (plus, for goto/switch, a few conservative
// straight-line edges). That property is what makes it safe for a "may be null"
// dataflow — an over-approximate CFG can only over-report nullness, never drop
// a null source that actually reaches a dereference.
type StmtNode struct {
	ID        int
	Kind      string // "entry", "exit", "join", or "stmt"
	StartLine int
	EndLine   int
	Stmt      parser.Node // source statement for "stmt" nodes; zero otherwise
	Succs     []int
}

// StmtCFG is a per-function statement-level CFG.
type StmtCFG struct {
	Nodes []*StmtNode
	Entry int
	Exit  int
}

// NodeAt returns the innermost real statement node containing line, or nil if
// no statement contains it. It prefers the smallest line range so a dereference
// inside a nested block resolves to the block's statement rather than an outer
// wrapper.
func (cfg *StmtCFG) NodeAt(line int) *StmtNode {
	var best *StmtNode
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		if line < n.StartLine || line > n.EndLine {
			continue
		}
		if best == nil || (n.EndLine-n.StartLine) < (best.EndLine-best.StartLine) {
			best = n
		}
	}
	return best
}

// Reaches reports whether there is a control-flow path from node from to node
// to (from == to counts as reached).
func (cfg *StmtCFG) Reaches(from, to int) bool {
	return cfg.ReachesAvoiding(from, nil, to)
}

// ReachesAvoiding reports whether to is reachable from from without traversing
// any node whose ID is in avoid. The start node from may not be in avoid. It
// answers "there exists a path", so callers use it to keep candidates unless
// they can prove the path is absent (a conservative direction for may-analyses).
func (cfg *StmtCFG) ReachesAvoiding(from int, avoid map[int]bool, to int) bool {
	if from < 0 || to < 0 || from >= len(cfg.Nodes) || to >= len(cfg.Nodes) {
		return false
	}
	if from == to {
		return true
	}
	if avoid[from] {
		return false
	}
	visited := make([]bool, len(cfg.Nodes))
	stack := []int{from}
	visited[from] = true
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, s := range cfg.Nodes[n].Succs {
			if s == to {
				return true
			}
			if visited[s] || avoid[s] {
				continue
			}
			visited[s] = true
			stack = append(stack, s)
		}
	}
	return false
}

type cfgBuilder struct {
	cfg     *StmtCFG
	exitID  int
	breakTo []int // innermost breakable exit: loop join OR switch join (break target)
	contTo  []int // innermost loop header (continue target)
}

// BuildStmtCFG builds a statement-level CFG for one function body. body is the
// function's compound_statement node; funcEnd is the function's closing line.
// If body is invalid (no compound_statement), it returns a CFG whose entry
// directly falls through to exit so callers degrade to a conservative path.
func BuildStmtCFG(body parser.Node, funcEnd int) *StmtCFG {
	cfg := &StmtCFG{}
	b := &cfgBuilder{cfg: cfg}

	cfg.Entry = b.newNode("entry", 0, 0, parser.Node{})
	cfg.Exit = b.newNode("exit", funcEnd, funcEnd, parser.Node{})
	b.exitID = cfg.Exit

	if body.Kind() != "compound_statement" {
		b.edge(cfg.Entry, cfg.Exit)
		return cfg
	}

	last := b.buildBlock(body, cfg.Entry)
	if last >= 0 {
		b.edge(last, cfg.Exit)
	}
	return cfg
}

func (b *cfgBuilder) newNode(kind string, start, end int, stmt parser.Node) int {
	id := len(b.cfg.Nodes)
	b.cfg.Nodes = append(b.cfg.Nodes, &StmtNode{
		ID:        id,
		Kind:      kind,
		StartLine: start,
		EndLine:   end,
		Stmt:      stmt,
	})
	return id
}

func (b *cfgBuilder) edge(from, to int) {
	if from < 0 || to < 0 {
		return
	}
	b.cfg.Nodes[from].Succs = append(b.cfg.Nodes[from].Succs, to)
}

// buildBlock builds a compound_statement's statement list. It returns the
// fall-through node (the node that continues after the block), or -1 if every
// live path in the block terminates (return/break/continue/goto).
func (b *cfgBuilder) buildBlock(body parser.Node, from int) int {
	last := from
	terminated := false
	for _, stmt := range body.NamedChildren() {
		if !isStmtNode(stmt) {
			continue
		}
		if terminated {
			break
		}
		next := b.build(stmt, last)
		if next < 0 {
			terminated = true
		} else {
			last = next
		}
	}
	if terminated {
		return -1
	}
	return last
}

// build builds the CFG fragment for a single statement, connecting it from
// `from`, and returns the statement's fall-through node (or -1 if it does not
// fall through to the next statement).
func (b *cfgBuilder) build(stmt parser.Node, from int) int {
	switch stmt.Kind() {
	case "compound_statement":
		return b.buildBlock(stmt, from)
	case "if_statement":
		return b.buildIf(stmt, from)
	case "while_statement", "do_statement":
		return b.buildWhileDo(stmt, from)
	case "for_statement":
		return b.buildFor(stmt, from)
	case "switch_statement":
		return b.buildSwitch(stmt, from)
	case "preproc_ifdef", "preproc_ifndef", "preproc_if":
		return b.buildPreproc(stmt, from)
	case "return_statement":
		n := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
		b.edge(from, n)
		b.edge(n, b.exitID)
		return -1
	case "break_statement":
		n := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
		b.edge(from, n)
		// break exits the INNERMOST breakable construct (loop or switch), which
		// is the top of breakTo. A loop nested inside a switch case must break
		// the loop, not the switch — so loops and switches share one stack.
		if len(b.breakTo) > 0 {
			b.edge(n, b.breakTo[len(b.breakTo)-1])
		} else {
			b.edge(n, b.exitID)
		}
		return -1
	case "continue_statement":
		n := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
		b.edge(from, n)
		if len(b.contTo) > 0 {
			b.edge(n, b.contTo[len(b.contTo)-1])
		} else {
			b.edge(n, b.exitID)
		}
		return -1
	case "goto_statement":
		// goto is rare in modern C. We treat it as fall-through (an over-
		// approximation for forward jumps); the labelled target is still
		// reached by straight-line order in the common forward case.
		n := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
		b.edge(from, n)
		return n
	case "labeled_statement":
		// A label is a no-op for control flow; the labelled statement follows.
		for _, child := range stmt.NamedChildren() {
			if isStmtNode(child) {
				return b.build(child, from)
			}
		}
		return from
	case "case_statement":
		// A case label is a no-op; its statements follow. Normally handled by
		// buildSwitch, but a case nested in a compound_statement still works.
		return b.buildBlock(stmt, from)
	default:
		// expression_statement, declaration, and anything unrecognised: a
		// straight-line leaf statement.
		n := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
		b.edge(from, n)
		return n
	}
}

func (b *cfgBuilder) buildIf(stmt parser.Node, from int) int {
	cond := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
	b.edge(from, cond)

	cons := stmt.ChildByFieldName("consequence")
	alt := elseBody(stmt)

	join := b.newNode("join", 0, 0, parser.Node{})

	thenLast := -1
	if cons != nil {
		thenLast = b.build(*cons, cond)
	}

	elseLast := -1
	if alt != nil {
		elseLast = b.build(*alt, cond)
	} else {
		// No else branch: the false path falls straight through to the join.
		b.edge(cond, join)
	}

	if thenLast >= 0 {
		b.edge(thenLast, join)
	}
	if elseLast >= 0 {
		b.edge(elseLast, join)
	}

	// Only dead-end if every live branch terminates.
	if thenLast < 0 && alt != nil && elseLast < 0 {
		return -1
	}
	return join
}

func (b *cfgBuilder) buildWhileDo(stmt parser.Node, from int) int {
	if stmt.Kind() == "do_statement" {
		return b.buildDo(stmt, from)
	}
	// while_statement
	header := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
	b.edge(from, header)

	join := b.newNode("join", 0, 0, parser.Node{})
	body := stmt.ChildByFieldName("body")

	b.breakTo = append(b.breakTo, join)
	b.contTo = append(b.contTo, header)

	bodyLast := -1
	if body != nil {
		bodyLast = b.build(*body, header)
	}

	b.breakTo = b.breakTo[:len(b.breakTo)-1]
	b.contTo = b.contTo[:len(b.contTo)-1]

	if bodyLast >= 0 {
		b.edge(bodyLast, header) // back edge
	}
	b.edge(header, join) // condition false → exit loop
	return join
}

func (b *cfgBuilder) buildDo(stmt parser.Node, from int) int {
	body := stmt.ChildByFieldName("body")
	cond := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)
	join := b.newNode("join", 0, 0, parser.Node{})

	b.breakTo = append(b.breakTo, join)
	b.contTo = append(b.contTo, cond)

	last := from
	firstID := -1
	terminated := false
	if body != nil {
		first := true
		for _, s := range body.NamedChildren() {
			if !isStmtNode(s) {
				continue
			}
			if terminated {
				break
			}
			// The next node created by build(s, ...) is the entry of s.
			pre := len(b.cfg.Nodes)
			next := b.build(s, last)
			if first {
				firstID = pre
				first = false
			}
			if next < 0 {
				terminated = true
			} else {
				last = next
			}
		}
	}

	b.breakTo = b.breakTo[:len(b.breakTo)-1]
	b.contTo = b.contTo[:len(b.contTo)-1]

	if firstID < 0 {
		firstID = cond // empty body: loop back to the condition itself
	}
	if !terminated {
		b.edge(last, cond)
	}
	b.edge(cond, firstID) // condition true → loop back
	b.edge(cond, join)    // condition false → exit
	return join
}

func (b *cfgBuilder) buildFor(stmt parser.Node, from int) int {
	init := stmt.ChildByFieldName("initializer")
	cond := stmt.ChildByFieldName("condition")
	body := stmt.ChildByFieldName("body")
	update := stmt.ChildByFieldName("update")

	header := b.newNode("stmt", stmt.StartLine(), stmt.EndLine(), stmt)

	// Initializer runs exactly once before the condition.
	cur := from
	if init != nil {
		cur = b.build(*init, cur)
	}
	b.edge(cur, header)

	join := b.newNode("join", 0, 0, parser.Node{})

	b.breakTo = append(b.breakTo, join)
	b.contTo = append(b.contTo, header)

	bodyLast := -1
	if body != nil {
		bodyLast = b.build(*body, header)
	}

	b.breakTo = b.breakTo[:len(b.breakTo)-1]
	b.contTo = b.contTo[:len(b.contTo)-1]

	// Update runs after each body iteration, before re-testing the condition.
	if bodyLast >= 0 {
		if update != nil {
			upd := b.newNode("stmt", update.StartLine(), update.EndLine(), *update)
			b.edge(bodyLast, upd)
			b.edge(upd, header)
		} else {
			b.edge(bodyLast, header)
		}
	}
	// A for loop exits via its condition becoming false. `for (;;)` has no
	// condition (nil), so it is an infinite loop with no natural exit — adding
	// a header→join edge there would fabricate a path that skips the body and
	// lets a kill inside the body be bypassed (false negative in the may
	// analysis). Only emit the exit edge when a condition exists.
	if cond != nil {
		b.edge(header, join)
	}
	return join
}

// buildSwitch builds a switch as: the switch entry reaches every case directly
// (the condition jumps to the matching case), consecutive cases fall through to
// one another, and a break inside a case exits to the switch's join. This is an
// over-approximation (the safe direction for may-analyses): a case is reachable
// from the entry even when an earlier case ends in break, because the jump path
// is always present.
func (b *cfgBuilder) buildSwitch(stmt parser.Node, from int) int {
	body := stmt.ChildByFieldName("body")
	join := b.newNode("join", 0, 0, parser.Node{})
	if body == nil {
		b.edge(from, join)
		return join
	}

	b.breakTo = append(b.breakTo, join)
	defer func() { b.breakTo = b.breakTo[:len(b.breakTo)-1] }()

	type caseInfo struct {
		first, last int // -1 when empty or terminated
	}
	var cases []caseInfo
	for _, child := range body.NamedChildren() {
		if child.Kind() != "case_statement" {
			continue
		}
		pre := len(b.cfg.Nodes)
		last := b.buildBlock(child, from) // jump: from -> the case's first statement
		first := -1
		if pre < len(b.cfg.Nodes) {
			first = pre
		}
		cases = append(cases, caseInfo{first: first, last: last})
	}

	// Fall-through: each non-terminating case's last statement reaches the next
	// case's first statement.
	for i := 1; i < len(cases); i++ {
		if cases[i-1].last >= 0 && cases[i].first >= 0 {
			b.edge(cases[i-1].last, cases[i].first)
		}
	}
	// The last non-terminating case falls through to the switch exit, and the
	// entry itself reaches the exit when no case matches.
	if n := len(cases); n > 0 && cases[n-1].last >= 0 {
		b.edge(cases[n-1].last, join)
	}
	b.edge(from, join)
	return join
}

// buildStmtList builds a straight-line sequence of statements from `from` and
// returns the fall-through node, or -1 if every live path terminates.
func (b *cfgBuilder) buildStmtList(stmts []parser.Node, from int) int {
	last := from
	terminated := false
	for _, stmt := range stmts {
		if terminated {
			break
		}
		next := b.build(stmt, last)
		if next < 0 {
			terminated = true
		} else {
			last = next
		}
	}
	if terminated {
		return -1
	}
	return last
}

// collectPreprocBranch returns the statement children of a #elif or #else node.
func collectPreprocBranch(node parser.Node) []parser.Node {
	var stmts []parser.Node
	for _, c := range node.NamedChildren() {
		if isStmtNode(c) {
			stmts = append(stmts, c)
		}
	}
	return stmts
}

// buildPreproc models a #ifdef/#ifndef/#if conditional as control-flow
// ALTERNATIVES: each compiled branch (then, every #elif, and #else) is an
// alternative from `from` to a common join, exactly like if/else. This matches
// the preprocessor semantics — exactly one branch is compiled — so a value
// written in EVERY branch is definitely written, while a value written in only
// one branch still reaches the join on the other branch. The previous behaviour
// skipped these nodes entirely, so a variable assigned in BOTH branches (e.g.
// zlib's `#ifdef UNALIGNED_OK ... #else len = ... #endif`) was reported as
// uninitialized.
func (b *cfgBuilder) buildPreproc(stmt parser.Node, from int) int {
	join := b.newNode("join", 0, 0, parser.Node{})

	var branches [][]parser.Node
	var cur []parser.Node
	sawElse := false

	flush := func() {
		branches = append(branches, cur)
		cur = nil
	}

	for _, child := range stmt.NamedChildren() {
		switch child.Kind() {
		case "preproc_elif":
			flush()
			cur = collectPreprocBranch(child)
			flush()
		case "preproc_else":
			flush()
			sawElse = true
			cur = collectPreprocBranch(child)
		default:
			// Skip the macro name / condition (identifier or expression) and
			// keep the statement children as the "then" branch.
			if isStmtNode(child) {
				cur = append(cur, child)
			}
		}
	}
	flush()

	if !sawElse {
		// The "not compiled" path is an empty alternative.
		branches = append(branches, nil)
	}

	anyFallThrough := false
	for _, br := range branches {
		if len(br) == 0 {
			b.edge(from, join)
			anyFallThrough = true
			continue
		}
		if last := b.buildStmtList(br, from); last >= 0 {
			b.edge(last, join)
			anyFallThrough = true
		}
	}
	if !anyFallThrough {
		return -1 // every branch terminates
	}
	return join
}

// isStmtNode reports whether a compound_statement child is a statement (rather
// than an anonymous brace/semicolon or a preprocessor region). Preprocessor
// conditionals (#ifdef/#ifndef/#if) ARE included: they are modelled as
// alternatives so a variable assigned in every branch is still recognized as
// definitely initialized. Their nested #else/#elif are handled inside
// buildPreproc, not as top-level children.
func isStmtNode(n parser.Node) bool {
	switch n.Kind() {
	case "declaration", "expression_statement", "if_statement", "for_statement",
		"while_statement", "do_statement", "switch_statement", "return_statement",
		"break_statement", "continue_statement", "goto_statement",
		"compound_statement", "labeled_statement", "case_statement",
		"preproc_ifdef", "preproc_ifndef", "preproc_if":
		return true
	}
	return false
}

// elseBody unwraps the else_clause wrapper to the statement that executes on
// the false path (a compound_statement, or a nested if_statement for else-if).
func elseBody(ifStmt parser.Node) *parser.Node {
	alt := ifStmt.ChildByFieldName("alternative")
	if alt == nil {
		return nil
	}
	if alt.Kind() == "else_clause" {
		for _, c := range alt.NamedChildren() {
			if isStmtNode(c) {
				return &c
			}
		}
		return nil
	}
	return alt
}
