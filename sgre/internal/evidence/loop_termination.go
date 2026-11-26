package evidence

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// LoopTerminationDetector flags loops whose exit condition cannot make progress
// (CWE-835 / CWE-834), the deterministic half of the "loop termination &
// progress" analysis. It is deliberately CONSERVATIVE and never auto-confirms:
// every candidate is handed to the AI as `suspected` because proving a loop
// never terminates requires ruling out pointer aliases, external state, and
// function side-effects the pipeline cannot model.
//
// Three defect shapes are recognized:
//
//   - no_progress: the loop's exit-condition variable (a bare local scalar) is
//     never assigned/updated anywhere in the loop body or update clause, and no
//     `break`/`return`/`goto` provides an alternative exit. If the loop is
//     entered it can never re-evaluate the condition differently.
//   - zero_step: the variable IS written, but every write is a provable no-op
//     (`v = v`, `v += 0`, `v -= 0`, `v *= 1`, `v /= 1`, `v <<= 0`, `v >>= 0`).
//   - continue_bypass: a while/do loop whose `continue` sits textually before
//     every write to the progress variable, so that back-edge skips the update.
//
// False-positive guards (per the issue's §5): constant-true loops
// (`while (1)`, `for (;;)`, `while (true)`) are skipped; only function-locals
// (parameters or locals, never globals) are tracked; a `break`/`return`/`goto`
// in the loop body suppresses `no_progress`/`zero_step`; an address-of (`&v`)
// anywhere in the loop suppresses all three (the value may be written through
// the alias).
type LoopTerminationDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewLoopTerminationDetector(store db.Store, p *parser.Parser, logger *log.Logger) *LoopTerminationDetector {
	return &LoopTerminationDetector{store: store, parser: p, logger: logger}
}

func (d *LoopTerminationDetector) Name() string { return "loop_termination" }

func (d *LoopTerminationDetector) Domain() string { return "control" }

func (d *LoopTerminationDetector) Capabilities() []string {
	return []string{"loop termination", "progress analysis", "CWE-835"}
}

func (d *LoopTerminationDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		globals, locals := collectFileScope(root, funcs)

		paramsByFn := map[int]map[string]bool{}
		for _, fd := range root.FindAll("function_definition") {
			_, names, _ := functionParamNames(fd)
			if len(names) == 0 {
				continue
			}
			for _, fn := range funcs {
				if fd.StartLine() >= fn.StartLine && fd.StartLine() <= fn.EndLine {
					m := paramsByFn[fn.StartLine]
					if m == nil {
						m = map[string]bool{}
						paramsByFn[fn.StartLine] = m
					}
					for _, n := range names {
						m[n] = true
					}
				}
			}
		}

		for _, kind := range []string{"while_statement", "for_statement", "do_statement"} {
			for _, loop := range root.FindAll(kind) {
				fn := ownerFunction(funcs, loop)
				if fn == nil {
					continue
				}
				d.analyzeLoop(ctx, file, fn, loop, kind, globals, locals, paramsByFn, &result)
			}
		}
	})
	return result, err
}

// analyzeLoop classifies one loop into the three progress-defect shapes and
// emits at most one event for it (the first shape that matches, in order of
// decreasing certainty: no_progress, zero_step, continue_bypass).
func (d *LoopTerminationDetector) analyzeLoop(ctx context.Context, file *db.File, fn *db.Function, loop parser.Node, kind string, globals map[string]string, locals map[int][]scopedVarDecl, paramsByFn map[int]map[string]bool, result *DetectResult) {
	cond := loop.ChildByFieldName("condition")
	if isInfiniteLoopCond(cond, kind) {
		return
	}
	v := condBareVar(cond)
	if v == "" {
		return
	}
	if !isTrackableLocal(v, fn, globals, locals, paramsByFn) {
		return
	}

	body := loop.ChildByFieldName("body")
	update := loop.ChildByFieldName("update")

	var bodyNode, updateNode parser.Node
	if body != nil {
		bodyNode = *body
	}
	if update != nil {
		updateNode = *update
	}

	// An address-of (&v) may let a callee or alias write v through a pointer the
	// pipeline cannot follow — the conservative gate the issue's §5 requires for
	// pointer-alias / unknown-function modification.
	if takesAddress(bodyNode, v) || takesAddress(updateNode, v) {
		return
	}

	writes := collectVarWrites(bodyNode, updateNode, v)
	hasExit := hasLoopExit(bodyNode)

	condText := strings.TrimSpace(cond.Text())

	switch {
	case len(writes) == 0 && !hasExit:
		d.emit(ctx, fn.ID, file, loop, "no_progress", v, condText, loopKindName(kind), 0, result)
	case allNoopWrites(writes) && !hasExit:
		d.emit(ctx, fn.ID, file, loop, "zero_step", v, condText, loopKindName(kind), writes[0].line, result)
	case kind != "for_statement" && len(writes) > 0:
		// In a for loop `continue` still runs the update clause, so only a
		// while/do loop's continue can skip the progress update.
		if continues := collectDirectStatements(bodyNode, "continue_statement"); len(continues) > 0 {
			minContinue := continues[0].StartLine()
			minWrite := writes[0].line
			if minContinue < minWrite {
				d.emit(ctx, fn.ID, file, loop, "continue_bypass", v, condText, loopKindName(kind), minContinue, result)
			}
		}
	}
}

func (d *LoopTerminationDetector) emit(ctx context.Context, fnID int64, file *db.File, loop parser.Node, category, variable, condText, loopKind string, progressLine int, result *DetectResult) {
	props := map[string]string{
		"category":       category,
		"variable":       variable,
		"expression":     loopHeaderText(loopKind, condText),
		"loop_kind":      loopKind,
		"loop_condition": condText,
	}
	if progressLine > 0 {
		props["progress_line"] = strconv.Itoa(progressLine)
	}
	if emitEvent(ctx, d.store, d.logger, "LOOP_TERMINATION", fnID, &db.Location{FileID: file.ID, Line: loop.StartLine(), Column: loop.StartColumn()}, props) {
		result.EventsCreated++
	}
}

// condBareVar returns the bare identifier a loop condition tests for progress
// (`i` in `while (i < n)`, `p` in `while (p < end)`, `len` in `while (len > 0)`,
// `v` in `while (v)` / `while (!v)`). It returns "" for a compound condition
// (`i < n && !done`), a field/subscript/deref test, or a call — those shapes are
// either flag-driven or alias-prone and are left to the AI.
func condBareVar(cond *parser.Node) string {
	if cond == nil {
		return ""
	}
	n := *cond
	for n.Kind() == "parenthesized_expression" {
		ch := n.NamedChildren()
		if len(ch) == 0 {
			return ""
		}
		n = ch[0]
	}
	switch n.Kind() {
	case "identifier":
		return n.Text()
	case "unary_expression":
		t := strings.TrimSpace(n.Text())
		if !strings.HasPrefix(t, "!") {
			return ""
		}
		for _, c := range n.NamedChildren() {
			if c.Kind() == "identifier" {
				return c.Text()
			}
		}
		return ""
	case "binary_expression":
		switch parser.BinaryOperator(n) {
		case "<", "<=", ">", ">=", "==", "!=":
			kids := n.NamedChildren()
			if len(kids) == 2 {
				if kids[0].Kind() == "identifier" {
					return kids[0].Text()
				}
				if kids[1].Kind() == "identifier" {
					return kids[1].Text()
				}
			}
		}
	}
	return ""
}

// isInfiniteLoopCond reports whether a loop condition is a compile-time-true
// constant (`while (1)`, `while (true)`, or the absent condition of `for (;;)`),
// which is an intentional infinite loop rather than a progress defect.
func isInfiniteLoopCond(cond *parser.Node, kind string) bool {
	if cond == nil {
		return kind == "for_statement"
	}
	n := *cond
	for n.Kind() == "parenthesized_expression" {
		ch := n.NamedChildren()
		if len(ch) == 0 {
			return false
		}
		n = ch[0]
	}
	switch n.Kind() {
	case "number_literal":
		t := strings.TrimSpace(n.Text())
		return t != "" && t != "0"
	case "identifier":
		return n.Text() == "true"
	}
	return false
}

// isTrackableLocal reports whether v is a function-local scalar whose value can
// only change through a direct write in this function: a parameter or a local
// declaration (not a file-scope global / extern, which another thread, callback
// or translation unit may modify).
func isTrackableLocal(v string, fn *db.Function, globals map[string]string, locals map[int][]scopedVarDecl, paramsByFn map[int]map[string]bool) bool {
	if _, isGlobal := globals[v]; isGlobal {
		return false
	}
	if paramsByFn[fn.StartLine][v] {
		return true
	}
	for _, d := range locals[fn.StartLine] {
		if d.name == v {
			return true
		}
	}
	return false
}

// varWrite is one write to the progress variable, classified as a provable
// no-op (cannot change the value) or an effective update.
type varWrite struct {
	line int
	noop bool
}

// collectVarWrites scans a loop body and (for a for-loop) its update clause for
// every assignment/update whose target is the bare identifier v. Recursing
// through the whole subtree (including nested loops and branches) over-
// approximates "written anywhere", which is the conservative direction for the
// "never written" test.
func collectVarWrites(body, update parser.Node, v string) []varWrite {
	var writes []varWrite
	var scan func(n parser.Node)
	scan = func(n parser.Node) {
		switch n.Kind() {
		case "assignment_expression":
			lhs, rhs, ok := n.AssignParts()
			if ok && lhs.Kind() == "identifier" && lhs.Text() == v {
				writes = append(writes, varWrite{line: n.StartLine(), noop: isNoopAssign(parser.AssignmentOperator(n), rhs, v)})
			}
		case "update_expression":
			for _, c := range n.Children() {
				if c.Kind() == "identifier" && c.Text() == v {
					writes = append(writes, varWrite{line: n.StartLine(), noop: false})
					break
				}
			}
		}
		for _, c := range n.NamedChildren() {
			scan(c)
		}
	}
	if body.Kind() != "" {
		scan(body)
	}
	if update.Kind() != "" {
		scan(update)
	}
	return writes
}

// isNoopAssign reports whether an assignment to v cannot change v's value:
// `v = v`, `v += 0`, `v -= 0`, `v <<= 0`, `v >>= 0`, `v *= 1`, `v /= 1`.
func isNoopAssign(op string, rhs parser.Node, v string) bool {
	switch op {
	case "=":
		r := rhs
		for r.Kind() == "parenthesized_expression" {
			ch := r.NamedChildren()
			if len(ch) == 0 {
				return false
			}
			r = ch[0]
		}
		return r.Kind() == "identifier" && r.Text() == v
	case "+=", "-=", "<<=", ">>=":
		return isIntLit(rhs, 0)
	case "*=", "/=":
		return isIntLit(rhs, 1)
	}
	return false
}

// isIntLit reports whether n is a numeric literal equal to want, through
// parentheses/casts (`(uint32_t)0`).
func isIntLit(n parser.Node, want int64) bool {
	for n.Kind() == "parenthesized_expression" || n.Kind() == "cast_expression" {
		ch := n.NamedChildren()
		if len(ch) == 0 {
			return false
		}
		n = ch[len(ch)-1]
	}
	if n.Kind() != "number_literal" {
		return false
	}
	val, err := strconv.ParseInt(strings.TrimSpace(n.Text()), 0, 64)
	return err == nil && val == want
}

func allNoopWrites(writes []varWrite) bool {
	if len(writes) == 0 {
		return false
	}
	for _, w := range writes {
		if !w.noop {
			return false
		}
	}
	return true
}

// collectDirectStatements returns the break/continue statements that belong to
// THIS loop, stopping the descent at a nested loop or switch (whose break/
// continue targets are the inner construct, not this loop).
func collectDirectStatements(body parser.Node, kind string) []parser.Node {
	var out []parser.Node
	var walk func(n parser.Node)
	walk = func(n parser.Node) {
		switch n.Kind() {
		case kind:
			out = append(out, n)
			return
		case "for_statement", "while_statement", "do_statement", "switch_statement":
			return
		}
		for _, c := range n.NamedChildren() {
			walk(c)
		}
	}
	if body.Kind() != "" {
		walk(body)
	}
	return out
}

// hasLoopExit reports whether the loop body contains a direct `break`,
// `return`, or `goto` — an alternative exit that can terminate the loop even
// when the exit condition never progresses. A `break` inside a nested loop or
// switch is excluded (it targets the inner construct).
func hasLoopExit(body parser.Node) bool {
	if len(collectDirectStatements(body, "break_statement")) > 0 ||
		len(collectDirectStatements(body, "return_statement")) > 0 ||
		len(collectDirectStatements(body, "goto_statement")) > 0 {
		return true
	}
	return false
}

// takesAddress reports whether an address-of (`&v`) appears in node — the
// signal that v's value may be written through a pointer the pipeline cannot
// follow. tree-sitter-c parses both `&v` (address-of) and `*p` (dereference)
// as a pointer_expression, so the leading `&` is what separates them.
func takesAddress(node parser.Node, v string) bool {
	if node.Kind() == "" {
		return false
	}
	for _, n := range node.FindAll("pointer_expression") {
		t := strings.TrimSpace(n.Text())
		if !strings.HasPrefix(t, "&") {
			continue
		}
		for _, c := range n.NamedChildren() {
			if c.Kind() == "identifier" && c.Text() == v {
				return true
			}
		}
	}
	return false
}

// ownerFunction returns the indexed function whose line range contains node.
func ownerFunction(funcs []*db.Function, node parser.Node) *db.Function {
	for _, fn := range funcs {
		if node.StartLine() >= fn.StartLine && node.StartLine() <= fn.EndLine {
			return fn
		}
	}
	return nil
}

func loopKindName(kind string) string {
	switch kind {
	case "while_statement":
		return "while"
	case "for_statement":
		return "for"
	case "do_statement":
		return "do"
	}
	return kind
}

func loopHeaderText(kind, condText string) string {
	switch kind {
	case "while":
		return "while (" + condText + ")"
	case "for":
		return "for (…; " + condText + "; …)"
	case "do":
		return "do … while (" + condText + ")"
	}
	return condText
}
