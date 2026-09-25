package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type NullGuardDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewNullGuardDetector(store db.Store, p *parser.Parser, logger *log.Logger) *NullGuardDetector {
	return &NullGuardDetector{store: store, parser: p, logger: logger}
}

func (d *NullGuardDetector) Name() string { return "null_guard" }

func (d *NullGuardDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Null-check predicate helpers (is_empty/has_null/...) are collected across
	// the whole scan tree before guard detection: a helper defined in a .h
	// header is indexed as a Function in another file, so the per-file callback
	// below could not see its body. The summary is consulted by detectHelperGuards.
	helpers, err := d.collectNullCheckHelpers(ctx, &result)
	if err != nil {
		return result, err
	}

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")
		macroGuards := macros.GuardSummaries(root)
		// Iterator-style guards live in loop conditions:
		//   while ((e = dictNext(di)) != NULL) { e->val; }
		// The loop body is only entered when the iterator returned non-null, so
		// a deref inside is guarded. if/while/for all expose a "condition" field.
		condNodes := append(append(append([]parser.Node{}, ifs...), whiles...), fors...)
		for _, f := range funcs {
			d.detectGuards(ctx, f, file, condNodes, assigns, &result)
			d.detectEarlyReturnGuards(ctx, f, file, ifs, assigns, &result)
			d.detectReassignmentGuards(ctx, f, file, ifs, assigns, &result)
			d.detectMacroGuards(ctx, f, file, calls, assigns, macroGuards, &result)
			d.detectHelperGuards(ctx, f, file, ifs, assigns, helpers, &result)
			d.detectAssertGuards(ctx, f, file, calls, assigns, &result)
		}
	})
	return result, err
}

// detectHelperGuards handles the indirect null-check via a predicate helper:
// `if (is_empty(p)) { goto/return/break/continue; }` where is_empty is a
// function that returns true when its parameter is NULL. The fall-through path
// therefore has p != NULL, so a later dereference of p is guarded. The helper
// body may live in another file (a .h header), so the cross-file helper
// summary is consulted instead of re-parsing the definition here.
func (d *NullGuardDetector) detectHelperGuards(ctx context.Context, f *db.Function, file *db.File, ifs, assigns []parser.Node, helpers map[string][]int, result *DetectResult) {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		cons := ifNode.ChildByFieldName("consequence")
		if cons == nil || !isExitBlock(*cons) {
			continue
		}
		cond := ifNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		call := findHelperCallInCond(*cond, helpers)
		if call == nil {
			continue
		}
		idxs := helpers[extractCallName(*call)]
		args := getCallArgs(*call)

		for _, idx := range idxs {
			if idx >= len(args) {
				continue
			}
			varName := bareVarName(args[idx])
			if varName == "" {
				continue
			}
			if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: ifNode.StartLine()}, map[string]interface{}{
				"variable":    varName,
				"condition":   "HELPER_GUARD",
				"scope_start": ifNode.EndLine() + 1,
				"scope_end":   guardScopeEnd(assigns, f, varName, ifNode.EndLine()),
			}) {
				result.EventsCreated++
			}
		}
	}
}

// isExitBlock reports whether an if-consequence exits the current scope on the
// taken branch (return / goto / break / continue). Only such an exit makes the
// fall-through path the non-null branch of a helper guard.
func isExitBlock(cons parser.Node) bool {
	switch cons.Kind() {
	case "return_statement", "goto_statement", "break_statement", "continue_statement":
		return true
	}
	for _, kind := range []string{"return_statement", "goto_statement", "break_statement", "continue_statement"} {
		if len(cons.FindAll(kind)) > 0 {
			return true
		}
	}
	return false
}

// findHelperCallInCond returns the predicate-helper call at the top of a guard
// condition (`if (is_empty(p))` / `if ((is_empty(p)))`), or nil. A negated
// helper (`!is_empty(p)`) is deliberately NOT matched: its fall-through is the
// NULL branch, so it does not establish non-null. Compound conditions
// (`is_empty(p) && x`) are also excluded — only a bare helper call gives a
// clean "helper true ⟹ param NULL" implication on the taken branch.
func findHelperCallInCond(cond parser.Node, helpers map[string][]int) *parser.Node {
	node := cond
	for node.Kind() == "parenthesized_expression" {
		children := node.NamedChildren()
		if len(children) == 0 {
			return nil
		}
		node = children[0]
	}
	if node.Kind() == "call_expression" {
		if _, ok := helpers[extractCallName(node)]; ok {
			n := node
			return &n
		}
	}
	return nil
}

func (d *NullGuardDetector) detectGuards(ctx context.Context, f *db.Function, file *db.File, condNodes, assigns []parser.Node, result *DetectResult) {
	for _, condNode := range condNodes {
		if !funcLineRange(f, condNode.StartLine()) {
			continue
		}
		condition := condNode.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		// Only a condition whose TRUE branch establishes a variable non-null is a
		// guard. `p != NULL` / `p` / `p && q` qualify; `p == NULL` / `!p` /
		// `p || q` establish NULL (or nothing) on the taken branch and must not
		// suppress a dereference inside it.
		vars := guardedNonnullVars(*condition)
		if len(vars) == 0 {
			continue
		}
		condPattern := classifyGuard(strings.TrimSpace(condition.Text()))

		// if uses "consequence", while/for use "body"; either delimits the
		// guarded scope.
		scopeEnd := f.EndLine
		if consequence := condNode.ChildByFieldName("consequence"); consequence != nil {
			scopeEnd = consequence.EndLine()
		} else if body := condNode.ChildByFieldName("body"); body != nil {
			scopeEnd = body.EndLine()
		}

		for _, varName := range vars {
			if varName == "" {
				continue
			}
			end := scopeEnd
			// A reassignment inside the guarded scope re-opens the null
			// possibility (`while (p != NULL) { ...; p = p->next; p->y; }`), so
			// truncate there exactly like the early-return guards do.
			if cut := guardScopeEnd(assigns, f, varName, condNode.StartLine()); cut < end {
				end = cut
			}
			if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: condNode.StartLine()}, map[string]interface{}{
				"variable":    varName,
				"condition":   condPattern,
				"scope_start": condNode.StartLine(),
				"scope_end":   end,
			}) {
				result.EventsCreated++
			}
		}
	}
}

// guardedNonnullVars returns the variables a condition establishes as non-null
// when it evaluates TRUE. It is the direction-aware, compound-aware core of
// detectGuards: a `&&` conjunction guards every operand, a `||` disjunction
// guards none (at most one operand need be non-null), `p != NULL` guards p, and
// `p == NULL` / `!p` establish NULL rather than non-null and guard nothing.
func guardedNonnullVars(cond parser.Node) []string {
	switch cond.Kind() {
	case "parenthesized_expression", "cast_expression":
		for _, c := range cond.NamedChildren() {
			if vars := guardedNonnullVars(c); len(vars) > 0 {
				return vars
			}
		}
		return nil
	}
	if cond.Kind() == "binary_expression" {
		switch binaryOperator(cond) {
		case "&&":
			var vars []string
			for _, child := range cond.NamedChildren() {
				vars = append(vars, guardedNonnullVars(child)...)
			}
			return vars
		case "||":
			return nil
		case "!=":
			if v := nonNullSideVar(cond); v != "" {
				return []string{v}
			}
		}
		return nil
	}
	if v := truthCheckedLvalue(cond); v != "" {
		return []string{v}
	}
	return nil
}

// nonNullSideVar returns the non-null operand of a `!=` comparison (`p != NULL`
// → p, `NULL != p` → p, `(e = f()) != NULL` → e), or "".
func nonNullSideVar(cond parser.Node) string {
	for _, c := range cond.NamedChildren() {
		if isNullOperand(c) {
			continue
		}
		if v := guardVarName(strings.TrimSpace(c.Text())); v != "" && v != "NULL" && v != "0" {
			return v
		}
	}
	return ""
}

// truthCheckedLvalue returns the lvalue path a bare truth-check tests (`if (p)`,
// `if (arr[i])`, `if (p->f)`), or "" for a negation (`!p` — establishes NULL),
// a dereference (`*pp` — tests the pointee, not pp), or any non-lvalue.
func truthCheckedLvalue(cond parser.Node) string {
	inner := cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			break
		}
		inner = kids[0]
	}
	if inner.Kind() == "unary_expression" {
		return ""
	}
	expr := strings.TrimSpace(inner.Text())
	if strings.HasPrefix(expr, "*") {
		return ""
	}
	return lvaluePath(expr)
}

func (d *NullGuardDetector) detectEarlyReturnGuards(ctx context.Context, f *db.Function, file *db.File, ifs, assigns []parser.Node, result *DetectResult) {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		consequence := ifNode.ChildByFieldName("consequence")
		if consequence == nil || !isExitBlock(*consequence) {
			continue
		}
		for _, varName := range earlyReturnGuardedVars(*condition) {
			if varName == "" {
				continue
			}
			scopeEnd := guardExitBound(*consequence, ifNode, f)
			if end := guardScopeEnd(assigns, f, varName, ifNode.EndLine()); end < scopeEnd {
				scopeEnd = end
			}
			if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: ifNode.StartLine()}, map[string]interface{}{
				"variable":    varName,
				"condition":   "EARLY_RETURN",
				"scope_start": ifNode.StartLine() + 1,
				"scope_end":   scopeEnd,
			}) {
				result.EventsCreated++
			}
		}
	}
}

// guardExitBound returns the outermost line through which an early-exit guard's
// non-null fact can hold on the fall-through. The fact holds only within the
// innermost enclosing block: a guard at the function top level spans the rest of
// the function, but a guard nested inside a conditional/loop branch
// (`if (c) { if (p == NULL) return; }`) must not leak its non-null fact past
// that branch — the branch may be skipped, leaving p NULL.
func guardExitBound(cons, ifNode parser.Node, f *db.Function) int {
	return enclosingBlockEnd(ifNode)
}

// earlyReturnGuardedVars returns the variables an early-return guard condition
// establishes as non-null. A top-level OR of null checks
// (`a == NULL || b == NULL`) returns on either null branch, so every operand's
// variable is non-null after the guard; a single null check (`p == NULL`, `!p`)
// guards its one variable. This is exactly the FALSE-direction of a condition
// (`p == NULL` false ⟹ p non-null), so it delegates to parser.NullCheckedVars —
// which also correctly rejects a conjunction (`p == NULL && x` false ⟹
// `p != NULL || !x`, neither operand guaranteed non-null).
func earlyReturnGuardedVars(cond parser.Node) []string {
	return parser.NullCheckedVars(cond)
}

// detectReassignmentGuards handles the null analogue of `if (x == 0) x = 1;`:
// `if (p == NULL) p = "";` (or `if (!p) p = &x;`) reassigns p to a provably
// non-null value on the null branch, so the FALL-THROUGH after the if is non-null
// on every path. The previous flow model accidentally covered this via a header
// node inheriting its body's assignment; that recursion was removed, so this
// detector emits the fall-through scope explicitly (like detectEarlyReturnGuards).
func (d *NullGuardDetector) detectReassignmentGuards(ctx context.Context, f *db.Function, file *db.File, ifs, assigns []parser.Node, result *DetectResult) {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		// An else branch means the non-null path is not the fall-through.
		if ifNode.ChildByFieldName("alternative") != nil {
			continue
		}
		cond := ifNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		// A reassignment guard (`if (p == NULL) p = &x;`) needs exactly ONE
		// null-checked variable; a conjunction (`p == NULL && q`) does not
		// establish p non-null on the fall-through, so it must not guard.
		vars := parser.NullCheckedVars(*cond)
		if len(vars) != 1 {
			continue
		}
		varName := vars[0]
		cons := ifNode.ChildByFieldName("consequence")
		if cons == nil || !assignsNonNull(*cons, varName) {
			continue
		}
		if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: ifNode.StartLine()}, map[string]interface{}{
			"variable":    varName,
			"condition":   "REASSIGN_GUARD",
			"scope_start": ifNode.EndLine() + 1,
			"scope_end":   guardScopeEnd(assigns, f, varName, ifNode.EndLine()),
		}) {
			result.EventsCreated++
		}
	}
}

// detectMacroGuards handles the guard-macro analogue of detectEarlyReturnGuards:
// a function-like macro whose body is `if (<cond>) return` (`#define CHECK_RET(c,
// r) if ((c)) { return r; }`) null-checks its argument and returns on the null
// branch, so a variable passed to it is non-null after the call. The macro body
// is not in the AST (tree-sitter parses the call site), so this consults the
// macro summary and re-derives the guarded variable from the call argument.
func (d *NullGuardDetector) detectMacroGuards(ctx context.Context, f *db.Function, file *db.File, calls, assigns []parser.Node, macroGuards map[string]macros.GuardSummary, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		// A guard macro is an early-return statement; only a call used as a whole
		// statement establishes a fall-through non-null scope.
		if p := call.Parent(); p == nil || p.Kind() != "expression_statement" {
			continue
		}
		guarded := macros.GuardedArgs(call, macroGuards)
		if len(guarded) == 0 {
			continue
		}
		args := getCallArgs(call)
		for idx, negated := range guarded {
			if idx >= len(args) {
				continue
			}
			var varName string
			if negated {
				varName = bareVarName(args[idx])
			} else {
				varName = parser.NullCheckedVariable(args[idx])
			}
			if varName == "" {
				continue
			}
			if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine()}, map[string]interface{}{
				"variable":    varName,
				"condition":   "MACRO_EARLY_RETURN",
				"scope_start": call.StartLine() + 1,
				"scope_end":   guardScopeEnd(assigns, f, varName, call.StartLine()),
			}) {
				result.EventsCreated++
			}
		}
	}
}

// detectAssertGuards handles assert(p != NULL) / assert(p) / assert(p != NULL
// && q != NULL): the assert aborts when the condition is false, so every
// variable the condition establishes as non-null is guarded on the fall-through
// (the code after the assert). assert(p == NULL) / assert(!p) assert NULL, not
// non-null, so they are NOT guards and yield nothing. assert is treated as a
// hard guard (the programmer's explicit precondition), matching the common
// enterprise C idiom where assert encodes a non-null contract.
func (d *NullGuardDetector) detectAssertGuards(ctx context.Context, f *db.Function, file *db.File, calls, assigns []parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if extractCallName(call) != "assert" {
			continue
		}
		if p := call.Parent(); p == nil || p.Kind() != "expression_statement" {
			continue
		}
		args := getCallArgs(call)
		if len(args) == 0 {
			continue
		}
		for _, varName := range assertGuardedVars(args[0]) {
			if varName == "" {
				continue
			}
			if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine()}, map[string]interface{}{
				"variable":    varName,
				"condition":   "ASSERT_GUARD",
				"scope_start": call.StartLine() + 1,
				"scope_end":   guardScopeEnd(assigns, f, varName, call.StartLine()),
			}) {
				result.EventsCreated++
			}
		}
	}
}

// assertGuardedVars returns the variables an assert condition establishes as
// non-null. assert(p != NULL) / assert(p) / assert(p != NULL && q != NULL)
// → [p] / [p] / [p, q]. assert(p == NULL) / assert(!p) → nil (these assert
// null, not non-null, so they do not guard a dereference).
func assertGuardedVars(cond parser.Node) []string {
	switch cond.Kind() {
	case "parenthesized_expression", "cast_expression":
		for _, c := range cond.NamedChildren() {
			if vars := assertGuardedVars(c); len(vars) > 0 {
				return vars
			}
		}
		return nil
	}
	if cond.Kind() == "binary_expression" && binaryOperator(cond) == "&&" {
		var vars []string
		for _, child := range cond.NamedChildren() {
			vars = append(vars, assertGuardedVars(child)...)
		}
		return vars
	}
	text := strings.TrimSpace(cond.Text())
	if strings.Contains(text, "!=") && (strings.Contains(text, "NULL") || strings.Contains(text, "0")) {
		if v := extractGuardedVariable(cond); v != "" {
			return []string{v}
		}
	}
	if v := bareVarName(cond); v != "" {
		return []string{v}
	}
	return nil
}

// bareVarName returns the variable name when arg is a bare identifier (possibly
// parenthesized), else "". It is the guard-macro companion to nullCheckedVariable
// for the `if (!param) return` form, where the caller passes the variable itself
// rather than a `var == NULL` expression.
func bareVarName(arg parser.Node) string {
	switch arg.Kind() {
	case "identifier":
		return arg.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range arg.NamedChildren() {
			if n := bareVarName(c); n != "" {
				return n
			}
		}
	}
	return ""
}

// guardScopeEnd truncates an early-return / reassignment guard's non-null scope
// at the first whole-variable reassignment of varName after afterLine (the
// guard's closing line). A reassignment invalidates the guard's non-null fact:
// `p = NULL` makes a later deref definitely null, and `p = malloc()` makes it
// possibly null — so the guard must not suppress a deref after it. It returns
// f.EndLine when no reassignment follows, preserving the full-scope behavior.
//
// A reassignment that executes only on an exiting path (`if (x) { p = NULL;
// return; }`) does NOT truncate the scope: the fall-through continuation never
// runs it, so p stays non-null there. Without this, the guarded-global idiom
// (`g = malloc(); if (g == NULL) return; ...; if (err) { g = NULL; return; }`)
// was misreported because the error branch's dead `g = NULL` cut the guard scope
// short.
func guardScopeEnd(assigns []parser.Node, f *db.Function, varName string, afterLine int) int {
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		if assign.StartLine() <= afterLine {
			continue
		}
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" && children[0].Text() == varName {
			if assignmentExitsScope(assign) {
				continue
			}
			return assign.StartLine() - 1
		}
	}
	return f.EndLine
}

// assignmentExitsScope reports whether an assignment executes only on a path that
// exits the function/loop scope (a return / goto / break / continue in the same
// branch), so it cannot reach the fall-through continuation an early-return guard
// protects. It walks up to the innermost enclosing branch: an assignment in an
// exiting if-branch is dead on the fall-through, while one in a non-exiting
// branch, a loop body, or the function's straight-line body is reachable and must
// truncate the guard scope.
func assignmentExitsScope(assign parser.Node) bool {
	child := assign
	for n := assign.Parent(); n != nil; n = n.Parent() {
		switch n.Kind() {
		case "if_statement":
			if cons := n.ChildByFieldName("consequence"); cons != nil && sameNode(*cons, child) {
				return isExitBlock(*cons)
			}
			if alt := n.ChildByFieldName("alternative"); alt != nil && sameNode(*alt, child) {
				return isExitBlock(*alt)
			}
			return false
		case "while_statement", "for_statement", "do_statement", "switch_statement":
			return false
		}
		child = *n
	}
	return false
}

// sameNode reports whether a and b denote the same tree node, by the byte range
// that uniquely identifies a node within one parse.
func sameNode(a, b parser.Node) bool {
	return a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

// assignsNonNull reports whether an if-consequence reassigns varName a provably
// non-null pointer (a string literal or an address-of).
func assignsNonNull(cons parser.Node, varName string) bool {
	for _, assign := range cons.FindAll("assignment_expression") {
		named := assign.NamedChildren()
		if len(named) < 2 {
			continue
		}
		if strings.TrimSpace(named[0].Text()) != varName {
			continue
		}
		if isNonNullExpr(named[1]) {
			return true
		}
	}
	return false
}

func isNonNullExpr(expr parser.Node) bool {
	switch expr.Kind() {
	case "string_literal", "compound_literal_expression":
		return true
	case "pointer_expression":
		return strings.HasPrefix(expr.Text(), "&")
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if isNonNullExpr(c) {
				return true
			}
		}
	}
	return false
}

func extractGuardedVariable(cond parser.Node) string {
	text := strings.TrimSpace(cond.Text())
	if text == "" {
		return ""
	}
	for _, op := range []string{"==", "!="} {
		if strings.Contains(text, op) {
			parts := strings.SplitN(text, op, 2)
			for _, p := range parts {
				p = guardVarName(p)
				if p != "" && p != "NULL" && p != "0" && p != "((void *)0)" {
					return p
				}
			}
		}
	}
	// Truth-check form (`if (p)`, `if (arr[i])`, `if (p->f)`): the condition's
	// expression IS the guarded lvalue, so return its path verbatim. A compound
	// path must be preserved because that is the name the dereference and
	// null-source detectors record for the same source text: for
	// `if (packet_queue[i]) { free(packet_queue[i]->data); }` the dereference
	// variable is `packet_queue[i]`. Recording only the first identifier
	// (`packet_queue`) made GuardFilter's exact-name match impossible, so every
	// guarded subscript/member access leaked a false candidate — and, in the
	// other direction, a guard on `p->f` used to match a dereference of `p`
	// (unrelated facts) and suppress a real finding.
	inner := cond
	for inner.Kind() == "parenthesized_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			break
		}
		inner = kids[0]
	}
	expr := strings.TrimSpace(inner.Text())
	if strings.HasPrefix(expr, "*") {
		// `if (*pp)` truth-checks the POINTEE. It establishes nothing about the
		// pointer pp, so recording pp as guarded would suppress a genuine
		// dereference of pp later in the block.
		return ""
	}
	if lv := lvaluePath(expr); lv != "" {
		return lv
	}
	idents := cond.FindAll("identifier")
	for _, id := range idents {
		name := id.Text()
		if name != "NULL" {
			return name
		}
	}
	return ""
}

// lvaluePath returns s when it is a plain C lvalue path — an identifier
// optionally followed by member (`->`, `.`) and subscript steps — and "" for
// anything else (a boolean combination, a call, a literal, a dereference). The
// text is returned unchanged, so it compares byte-for-byte with the name the
// dereference and null-source detectors derive from the same source text.
func lvaluePath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || !isCIdentStart(s[0]) {
		return ""
	}
	i := 0
	expectIdent := true
	for i < len(s) {
		if expectIdent {
			if !isCIdentStart(s[i]) {
				return ""
			}
			for i < len(s) && isCIdentPart(s[i]) {
				i++
			}
			expectIdent = false
			continue
		}
		switch {
		case strings.HasPrefix(s[i:], "->"):
			i += 2
			expectIdent = true
		case s[i] == '.':
			i++
			expectIdent = true
		case s[i] == '[':
			// The index expression is opaque here; it only has to be balanced.
			depth := 0
			for i < len(s) {
				switch s[i] {
				case '[':
					depth++
				case ']':
					depth--
				}
				i++
				if depth == 0 {
					break
				}
			}
			if depth != 0 {
				return ""
			}
		default:
			return ""
		}
	}
	if expectIdent {
		return "" // trailing `->` / `.`
	}
	return s
}

func isCIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isCIdentPart(c byte) bool {
	return isCIdentStart(c) || (c >= '0' && c <= '9')
}

// guardVarName normalises one operand of a null comparison: it trims
// parentheses and, for an assignment-in-condition (`(e = dictNext()) != NULL`),
// returns the assignment target `e` rather than the whole `e = dictNext()`.
func guardVarName(operand string) string {
	t := strings.TrimSpace(operand)
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	// A lone leading/trailing parenthesis remains when the "=="/"!=" split cut a
	// parenthesized condition like `(p == NULL)` into `"(p "` + `" NULL)"`. Strip
	// it: a guard variable is a C identifier and never carries parentheses, so
	// this cannot over-trim a real name.
	t = strings.Trim(t, "()")
	if i := strings.Index(t, "="); i > 0 {
		t = strings.TrimSpace(t[:i])
	}
	t = strings.TrimPrefix(t, "*")
	return strings.TrimSpace(t)
}

func classifyGuard(condText string) string {
	condText = strings.TrimSpace(condText)
	if strings.Contains(condText, "==") {
		if strings.Contains(condText, "NULL") || strings.Contains(condText, "0") {
			return "NULL_CHECK"
		}
	}
	if strings.Contains(condText, "!=") {
		if strings.Contains(condText, "NULL") || strings.Contains(condText, "0") {
			return "NULL_CHECK"
		}
	}
	return "TRUTH_CHECK"
}
