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
	helpers := d.collectNullCheckHelpers(ctx)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
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
			d.detectGuards(ctx, f, file, condNodes, &result)
			d.detectEarlyReturnGuards(ctx, f, file, ifs, assigns, &result)
			d.detectReassignmentGuards(ctx, f, file, ifs, assigns, &result)
			d.detectMacroGuards(ctx, f, file, calls, assigns, macroGuards, &result)
			d.detectHelperGuards(ctx, f, file, ifs, assigns, helpers, &result)
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

func (d *NullGuardDetector) detectGuards(ctx context.Context, f *db.Function, file *db.File, ifs []parser.Node, result *DetectResult) {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		condText := condition.Text()
		varName := extractGuardedVariable(*condition)
		if varName == "" {
			continue
		}
		condPattern := classifyGuard(condText)
		if condPattern == "" {
			continue
		}

		// if uses "consequence", while/for use "body"; either delimits the
		// guarded scope.
		scopeEnd := f.EndLine
		if consequence := ifNode.ChildByFieldName("consequence"); consequence != nil {
			scopeEnd = consequence.EndLine()
		} else if body := ifNode.ChildByFieldName("body"); body != nil {
			scopeEnd = body.EndLine()
		}

		if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: ifNode.StartLine()}, map[string]interface{}{
			"variable":    varName,
			"condition":   condPattern,
			"scope_start": ifNode.StartLine(),
			"scope_end":   scopeEnd,
		}) {
			result.EventsCreated++
		}
	}
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
		if consequence == nil || !strings.Contains(consequence.Text(), "return") {
			continue
		}
		for _, varName := range earlyReturnGuardedVars(*condition) {
			if varName == "" {
				continue
			}
			if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: ifNode.StartLine()}, map[string]interface{}{
				"variable":    varName,
				"condition":   "EARLY_RETURN",
				"scope_start": ifNode.StartLine() + 1,
				"scope_end":   guardScopeEnd(assigns, f, varName, ifNode.EndLine()),
			}) {
				result.EventsCreated++
			}
		}
	}
}

// earlyReturnGuardedVars returns the variables an early-return guard condition
// establishes as non-null. A top-level OR of null checks
// (`a == NULL || b == NULL`) returns on either null branch, so every operand's
// variable is non-null after the guard; a single null check (`p == NULL`, `!p`)
// guards its one variable.
func earlyReturnGuardedVars(cond parser.Node) []string {
	switch cond.Kind() {
	case "parenthesized_expression", "cast_expression":
		for _, c := range cond.NamedChildren() {
			if vars := earlyReturnGuardedVars(c); len(vars) > 0 {
				return vars
			}
		}
		return nil
	}
	if cond.Kind() == "binary_expression" && binaryOperator(cond) == "||" {
		var vars []string
		for _, child := range cond.NamedChildren() {
			vars = append(vars, earlyReturnGuardedVars(child)...)
		}
		return vars
	}
	if v := nullCheckedVariable(cond); v != "" {
		return []string{v}
	}
	return nil
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
		varName := nullCheckedVariable(*cond)
		if varName == "" {
			continue
		}
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
				varName = nullCheckedVariable(args[idx])
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
			return assign.StartLine() - 1
		}
	}
	return f.EndLine
}

// nullCheckedVariable returns the variable a null-check guard tests when the
// condition is `p == NULL`, `NULL == p`, `p == 0`, `0 == p`, or `!p`.
func nullCheckedVariable(cond parser.Node) string {
	t := strings.TrimSpace(cond.Text())
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	if strings.HasPrefix(t, "!") {
		v := strings.Trim(strings.TrimSpace(t[1:]), "()")
		if v != "" && v != "NULL" && v != "0" {
			return v
		}
		return ""
	}
	if strings.Contains(t, "==") {
		parts := strings.SplitN(t, "==", 2)
		for _, p := range parts {
			p = strings.Trim(strings.TrimSpace(p), "()")
			if p != "" && p != "NULL" && p != "0" && p != "((void*)0)" && p != "((void *)0)" {
				return p
			}
		}
	}
	return ""
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
	idents := cond.FindAll("identifier")
	for _, id := range idents {
		name := id.Text()
		if name != "NULL" {
			return name
		}
	}
	return ""
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
