package planner

import (
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
// true and false branches. A bare predicate-helper call (`is_empty(p)`) is
// treated as "true ⟺ param NULL", so its false branch proves the checked
// argument non-null.
func conditionGuardVars(cond parser.Node, helperParams map[string][]int) (trueVars, falseVars []string) {
	if name, args := bareHelperCall(cond, helperParams); name != "" {
		for _, idx := range helperParams[name] {
			if idx >= len(args) {
				continue
			}
			if v := parser.NullCheckedVariable(args[idx]); v != "" {
				falseVars = append(falseVars, v)
			}
		}
		return nil, falseVars
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

// bareHelperCall returns the helper name and its arguments when cond is a bare
// call to a known null-check predicate helper (`if (is_empty(p))`), unwrapping
// parentheses/casts. A negated (`!is_empty(p)`) or compound (`is_empty(p) && x`)
// call is NOT matched: only a bare call gives a clean "helper true ⟹ param NULL"
// implication.
func bareHelperCall(cond parser.Node, helperParams map[string][]int) (string, []parser.Node) {
	inner := cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			return "", nil
		}
		inner = kids[0]
	}
	if inner.Kind() != "call_expression" {
		return "", nil
	}
	name := callName(inner)
	if _, ok := helperParams[name]; !ok {
		return "", nil
	}
	return name, callArgs(inner)
}

// collectNullCheckHelpers gathers, across the whole scan tree, the "null-check
// predicate" functions: a function whose body returns true when one of its
// pointer parameters is NULL (`bool is_empty(T *p) { return p == NULL || ...; }`).
// A caller `if (is_empty(x)) { goto/return; }` therefore establishes x != NULL on
// the fall-through. Returns map[function name] -> 0-based parameter indices the
// function null-checks.
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
			if returnNullChecksParam(body, pn) {
				checked = append(checked, i)
			}
		}
		if len(checked) > 0 {
			out[fn.Name] = checked
		}
	}
	return out
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
