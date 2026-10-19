package planner

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// guardModel is the CFG-native replacement for the old line-range GuardFilter.
// A null guard is a path-sensitive fact: `if (p != NULL) { B }` proves p non-null
// only on the edge into B, and `if (p == NULL) return;` proves p non-null only on
// the fall-through (false) edge. The model records, per CFG edge, which
// variables' null source is killed on that edge; scope is therefore determined by
// the CFG (dominance + branch structure), not by line ranges.
type guardModel struct {
	// edgeKills maps (from, to) node IDs to the variables whose null source is
	// killed on that specific edge.
	edgeKills map[[2]int]map[string]bool
}

// buildGuardModel scans a CFG and derives the non-null facts its conditions and
// guard statements establish. helperParams is the cross-file predicate-helper
// summary (helper name -> null-checked parameter indices); macroGuards is the
// cross-file guard-macro summary.
func buildGuardModel(cfg *graph.StmtCFG, helperParams map[string][]int, macroGuards map[string]macros.GuardSummary) *guardModel {
	gm := &guardModel{edgeKills: make(map[[2]int]map[string]bool)}
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		if isConditionKind(n.Stmt.Kind()) {
			cond := n.Stmt.ChildByFieldName("condition")
			if cond == nil {
				continue
			}
			trueVars, falseVars := conditionGuardVars(*cond, helperParams)
			for _, t := range n.TrueSuccs {
				gm.addKills(n.ID, t, trueVars)
			}
			for _, f := range n.FalseSuccs {
				gm.addKills(n.ID, f, falseVars)
			}
			continue
		}
		// A straight-line guard statement (assert(p != NULL), a guard macro call)
		// establishes its variables non-null on every outgoing edge.
		if vars := statementGuardVars(n.Stmt, macroGuards); len(vars) > 0 {
			for _, succ := range n.Succs {
				gm.addKills(n.ID, succ, vars)
			}
		}
	}
	return gm
}

func (gm *guardModel) addKills(from, to int, vars []string) {
	for _, v := range vars {
		if v == "" {
			continue
		}
		key := [2]int{from, to}
		if gm.edgeKills[key] == nil {
			gm.edgeKills[key] = make(map[string]bool)
		}
		gm.edgeKills[key][v] = true
	}
}

// conditionGuardVars returns the variables a condition proves non-null on its
// true and false branches. A null-check-helper call establishes "helper(p)
// truthy/non-zero ⟺ p NULL", so `if (is_empty(p))` / `if (check(p) != 0)`
// proves the checked argument non-null on the FALSE branch, while
// `if (check(p) == 0)` / `if (!check(p))` proves it on the TRUE branch.
func conditionGuardVars(cond parser.Node, helperParams map[string][]int) (trueVars, falseVars []string) {
	if name, args, guardTrue := helperGuard(cond, helperParams); name != "" {
		for _, idx := range helperParams[name] {
			if idx >= len(args) {
				continue
			}
			if v := parser.NullCheckedVariable(args[idx]); v != "" {
				if guardTrue {
					trueVars = append(trueVars, v)
				} else {
					falseVars = append(falseVars, v)
				}
			}
		}
		return trueVars, falseVars
	}
	return parser.GuardedNonnullVars(cond), parser.NullCheckedVars(cond)
}

// statementGuardVars returns the variables a guard statement (`assert(...)` /
// a guard-macro call) establishes non-null on its fall-through.
func statementGuardVars(stmt parser.Node, macroGuards map[string]macros.GuardSummary) []string {
	var vars []string
	for _, call := range stmt.FindAll("call_expression") {
		name := callName(call)
		if name == "assert" {
			if args := callArgs(call); len(args) > 0 {
				vars = append(vars, parser.GuardedNonnullVars(args[0])...)
			}
			continue
		}
		if len(macroGuards) == 0 {
			continue
		}
		guarded := macros.GuardedArgs(call, macroGuards)
		if len(guarded) == 0 {
			continue
		}
		args := callArgs(call)
		for idx := range guarded {
			if idx >= len(args) {
				continue
			}
			if v := parser.NullCheckedVariable(args[idx]); v != "" {
				vars = append(vars, v)
			}
		}
	}
	return vars
}

// helperGuard returns the helper name, its arguments, and whether the guard's
// TRUE branch establishes the checked argument non-null, when cond is a guard
// built from a call to a known null-check helper. The shapes are:
//
//	if (f(p))        → false branch proves p non-null (guardTrue = false)
//	if (f(p) != 0)   → false branch proves p non-null (guardTrue = false)
//	if (f(p) == 0)   → true  branch proves p non-null (guardTrue = true)
//	if (!f(p))       → true  branch proves p non-null (guardTrue = true)
//
// A compound condition (`f(p) && x`, `f(p) || x`) is NOT matched: only a lone
// helper call gives the clean "helper non-zero ⟹ param NULL" implication.
func helperGuard(cond parser.Node, helperParams map[string][]int) (string, []parser.Node, bool) {
	inner := cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			return "", nil, false
		}
		inner = kids[0]
	}
	// Bare call `f(p)`.
	if inner.Kind() == "call_expression" {
		name := callName(inner)
		if _, ok := helperParams[name]; !ok {
			return "", nil, false
		}
		return name, callArgs(inner), false
	}
	// Negation `!f(p)`.
	if inner.Kind() == "unary_expression" {
		for _, c := range inner.NamedChildren() {
			if c.Kind() != "call_expression" {
				continue
			}
			if name := callName(c); name != "" {
				if _, ok := helperParams[name]; ok {
					return name, callArgs(c), true
				}
			}
		}
		return "", nil, false
	}
	// Comparison `f(p) == 0` / `f(p) != 0` (either operand order).
	if inner.Kind() != "binary_expression" {
		return "", nil, false
	}
	op := parser.BinaryOperator(inner)
	if op != "==" && op != "!=" {
		return "", nil, false
	}
	children := inner.NamedChildren()
	if len(children) != 2 {
		return "", nil, false
	}
	for i, c := range children {
		if !parser.IsNullOperand(c) {
			continue
		}
		callNode := children[1-i]
		for callNode.Kind() == "parenthesized_expression" || callNode.Kind() == "cast_expression" {
			kids := callNode.NamedChildren()
			if len(kids) == 0 {
				return "", nil, false
			}
			callNode = kids[0]
		}
		if callNode.Kind() != "call_expression" {
			return "", nil, false
		}
		name := callName(callNode)
		if _, ok := helperParams[name]; !ok {
			return "", nil, false
		}
		return name, callArgs(callNode), op == "=="
	}
	return "", nil, false
}

// collectNullCheckHelpers gathers, across the whole scan tree, the "null-check
// helper" functions: a function that establishes one of its pointer parameters
// is NULL ⟹ the function returns a non-zero/false status. Two shapes qualify:
//
//   - a predicate whose body returns true when the parameter is NULL
//     (`bool is_empty(T *p) { return p == NULL || ...; }`);
//   - a check/prepare function that null-guards the parameter at entry and
//     returns an error status (`int check(T *p, ...) { if (p == NULL) return -1; ... }`).
//
// A caller `if (helper(x)) { goto/return; }` / `if (helper(x) != 0) return;`
// therefore establishes x != NULL on the fall-through. Returns map[function
// name] -> 0-based parameter indices the function null-checks.
func collectNullCheckHelpers(cache *fileParseCache, funcs []*db.Function, fileByID map[int64]*db.File) map[string][]int {
	out := make(map[string][]int)
	for _, fn := range funcs {
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		params := paramListOf(fn, root)
		if len(params) == 0 {
			continue
		}
		var checked []int
		for i, pn := range params {
			if pn == "" {
				continue
			}
			if returnNullChecksParam(body, pn) || nullGuardEarlyErrorReturn(body, pn) {
				checked = append(checked, i)
			}
		}
		if len(checked) > 0 {
			out[fn.Name] = checked
		}
	}
	return out
}

// nullGuardEarlyErrorReturn reports whether body contains a null-guard on param
// that exits early with a non-zero (error) status — `if (param == NULL) return
// ERR;` or `if (!param) return -1;` — establishing "param NULL ⟹ the function
// returns non-zero", the check-function counterpart of the predicate helper.
func nullGuardEarlyErrorReturn(body parser.Node, param string) bool {
	for _, ifStmt := range body.FindAll("if_statement") {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil || !condNullChecksParam(*cond, param) {
			continue
		}
		cons := ifStmt.ChildByFieldName("consequence")
		if cons != nil && exitsEarlyNonZero(*cons) {
			return true
		}
	}
	return false
}

// condNullChecksParam reports whether a guard condition is a bare null-check of
// param (`param == NULL` / `NULL == param` / `!param`), not a compound or field
// access. A field check (`param->f == NULL`) tests the field, not the parameter.
func condNullChecksParam(cond parser.Node, param string) bool {
	inner := cond
	for inner.Kind() == "parenthesized_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			return false
		}
		inner = kids[0]
	}
	if inner.Kind() == "binary_expression" && parser.BinaryOperator(inner) == "==" {
		var hasParam, hasNull bool
		for _, op := range inner.NamedChildren() {
			if op.Kind() == "identifier" && op.Text() == param {
				hasParam = true
			}
			if parser.IsNullOperand(op) {
				hasNull = true
			}
		}
		return hasParam && hasNull
	}
	// Only the `!` operator null-checks; `*param` / `-param` / `+param` test or
	// transform the value rather than its nullness.
	if inner.Kind() == "unary_expression" && strings.HasPrefix(strings.TrimSpace(inner.Text()), "!") {
		for _, op := range inner.NamedChildren() {
			if op.Kind() == "identifier" && op.Text() == param {
				return true
			}
		}
	}
	return false
}

// exitsEarlyNonZero reports whether a guarded consequence exits early with a
// non-zero (error) status: a bare `return;` / `return ERR;` / `return -1;`, a
// break/continue/goto, or a compound block containing such an exit. `return 0;`
// is success-on-null and does NOT establish the error contract.
func exitsEarlyNonZero(stmt parser.Node) bool {
	switch stmt.Kind() {
	case "break_statement", "continue_statement", "goto_statement":
		return true
	case "return_statement":
		children := stmt.NamedChildren()
		if len(children) == 0 {
			return true
		}
		return !zeroLiteral(children[0])
	case "compound_statement":
		for _, child := range stmt.NamedChildren() {
			if exitsEarlyNonZero(child) {
				return true
			}
		}
	}
	return false
}

// zeroLiteral reports whether node is the integer literal 0.
func zeroLiteral(n parser.Node) bool {
	return n.Kind() == "number_literal" && strings.TrimSpace(n.Text()) == "0"
}

// returnNullChecksParam reports whether any return statement in body null-checks
// param (`return param == NULL` / `return !param` / a compound form).
func returnNullChecksParam(body parser.Node, param string) bool {
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		if parser.ExprNullChecksParam(children[0], param) {
			return true
		}
	}
	return false
}

// paramListOf returns the ordered parameter names of the function whose
// definition starts at fn.StartLine.
func paramListOf(fn *db.Function, root parser.Node) []string {
	for _, def := range root.FindAll("function_definition") {
		if def.StartLine() != fn.StartLine {
			continue
		}
		return paramNamesOfDef(def)
	}
	return nil
}

// collectMacroGuards merges per-file guard-macro summaries across the whole scan
// tree so a guard macro defined in a .h header is visible at call sites in every
// .c source.
func collectMacroGuards(cache *fileParseCache, fileByID map[int64]*db.File) map[string]macros.GuardSummary {
	out := make(map[string]macros.GuardSummary)
	for _, file := range fileByID {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		for name, s := range macros.GuardSummaries(root) {
			out[name] = s
		}
	}
	return out
}

// isConditionKind reports whether a statement node kind is a control-flow
// condition header whose true/false branches the CFG records. do_statement is
// excluded: its body runs before the condition is evaluated, so it establishes
// no non-null fact on entry (matching the retired line-based detector).
func isConditionKind(kind string) bool {
	switch kind {
	case "if_statement", "while_statement", "for_statement":
		return true
	}
	return false
}
