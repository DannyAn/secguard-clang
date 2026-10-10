package planner

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// globalInvariants captures cross-function non-zero invariants on global
// variables and struct fields. A global/field that is assigned only after a
// zero-check guard (`if (x == 0) return; g = x;`) or a default-backfill
// (`if (x == 0) x = DEFAULT; g = x;`) is non-zero at every use site that runs
// after the establishing function. This lets the divide-by-zero filter dismiss
// a `data / g_count` false positive where g_count is proven non-zero by
// construction in the registration/init function.
type globalInvariants struct {
	nonZeroVars map[string]bool
}

func newGlobalInvariants() *globalInvariants {
	return &globalInvariants{nonZeroVars: make(map[string]bool)}
}

// buildGlobalInvariants scans every function for patterns that establish a
// global/field as non-zero:
//
//	if (x == 0) return/continue/break; ... g = x;        → g non-zero
//	if (x == 0) x = DEFAULT; g = x;                      → g non-zero
//	if (x * y == 0) return;                              → x, y non-zero (if globals)
//	g->field = x;  after `if (x == 0) return;`           → g->field non-zero
//	g = nonZeroFunc();  (all assignments non-zero)        → g non-zero
//	g->field = 42;       (all assignments non-zero)        → g->field non-zero
//
// The last two patterns (non-zero-source assignments) require a whole-program
// pass: a target is marked non-zero only when EVERY assignment to it across
// the entire scan tree is from a provably non-zero source (non-zero literal,
// non-zero constant, sizeof, or a call to a function that provably returns
// non-zero). If any assignment is from an unknown source, the target stays
// unmarked — the conservative outcome.
func buildGlobalInvariants(ctx context.Context, store db.Store, p *parser.Parser, resolver *returnSummaryResolver) *globalInvariants {
	inv := newGlobalInvariants()
	if p == nil {
		return inv
	}
	files, err := store.ListFiles(ctx)
	if err != nil {
		return inv
	}
	cache := newFileParseCache(p)
	for _, file := range files {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		scanInvariants(root, inv)
	}
	scanNonZeroSourceAssignments(ctx, store, p, resolver, inv)
	return inv
}

// scanNonZeroSourceAssignments marks a field/global target as non-zero when
// ALL assignments to it are from provably non-zero sources. This is
// complementary to scanZeroGuardedAssignments: the zero-guarded pattern handles
// `if (x == 0) return; g = x;`, while this handles `g = get_count()` /
// `g = 42`. The two never conflict — a target with a zero-guarded assignment
// from a parameter (not "obviously non-zero") simply isn't marked by this pass,
// but may already be marked by the zero-guarded pass.
func scanNonZeroSourceAssignments(ctx context.Context, store db.Store, p *parser.Parser, resolver *returnSummaryResolver, inv *globalInvariants) {
	if resolver == nil {
		return
	}
	files, err := store.ListFiles(ctx)
	if err != nil {
		return
	}
	cache := newFileParseCache(p)
	type targetInfo struct {
		hasAssignment bool
		allNonZero    bool
	}
	targets := map[string]*targetInfo{}
	for _, file := range files {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		for _, assign := range root.FindAll("assignment_expression") {
			if !isSimpleAssign(assign) {
				continue
			}
			children := assign.NamedChildren()
			if len(children) < 2 {
				continue
			}
			lhs, rhs := children[0], children[1]
			target := assignTargetText(lhs)
			if target == "" {
				continue
			}
			info := targets[target]
			if info == nil {
				info = &targetInfo{allNonZero: true}
				targets[target] = info
			}
			info.hasAssignment = true
			if !isNonZeroSource(rhs, resolver) {
				info.allNonZero = false
			}
		}
	}
	for target, info := range targets {
		if info.hasAssignment && info.allNonZero {
			inv.nonZeroVars[target] = true
		}
	}
}

// isSimpleAssign reports whether an assignment_expression uses the `=` operator
// (not `+=`, `-=`, `/=`, etc.).
func isSimpleAssign(assign parser.Node) bool {
	for _, child := range assign.Children() {
		if child.Kind() == "=" {
			return true
		}
	}
	return false
}

// isNonZeroSource reports whether an RHS expression is provably non-zero: a
// non-zero literal, a non-zero constant symbol, a sizeof expression, or a call
// to a function that provably returns non-zero.
func isNonZeroSource(rhs parser.Node, resolver *returnSummaryResolver) bool {
	text := strings.TrimSpace(rhs.Text())
	if parser.NonZeroConstantValue(text) {
		return true
	}
	if strings.Contains(text, "sizeof") {
		return true
	}
	if resolver.globalConsts != nil {
		if resolver.globalConsts.NonZero(text) || resolver.globalConsts.NonZeroExpr(text) {
			return true
		}
	}
	if name := rhsCallName(rhs); name != "" && resolver.nonZeroReturn(name) {
		return true
	}
	return false
}

func scanInvariants(root parser.Node, inv *globalInvariants) {
	for _, fn := range root.FindAll("function_definition") {
		body := fn.FindFirst("compound_statement")
		if body == nil {
			continue
		}
		scanZeroGuardedAssignments(*body, inv)
	}
}

// scanZeroGuardedAssignments finds `if (x == 0) return; ... g = x;` and
// `if (x == 0) x = DEFAULT; ... g = x;` patterns, recording g as non-zero.
func scanZeroGuardedAssignments(body parser.Node, inv *globalInvariants) {
	ifs := body.FindAll("if_statement")
	for _, ifStmt := range ifs {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		guarded := zeroGuardedVarAST(*cond)
		if len(guarded) == 0 {
			continue
		}
		consequence := ifStmt.ChildByFieldName("consequence")
		if consequence == nil {
			continue
		}
		if !exitsEarly(*consequence) && !backfillsToNonZero(*consequence, guarded) {
			continue
		}
		for _, varName := range guarded {
			recordNonZeroAssignsAfter(body, ifStmt.EndLine(), varName, inv)
		}
	}
}

// zeroGuardedVarAST returns variables established as zero by a condition
// (`x == 0`, `0 == x`, `!x`, `x * y == 0`).
func zeroGuardedVarAST(cond parser.Node) []string {
	for cond.Kind() == "parenthesized_expression" {
		ch := cond.NamedChildren()
		if len(ch) == 0 {
			return nil
		}
		cond = ch[0]
	}
	if cond.Kind() == "unary_expression" && strings.HasPrefix(strings.TrimSpace(cond.Text()), "!") {
		for _, c := range cond.NamedChildren() {
			if name := bareOperandVar(c); name != "" {
				return []string{name}
			}
		}
	}
	if cond.Kind() == "binary_expression" {
		op := parser.BinaryOperator(cond)
		if op == "==" {
			for _, c := range cond.NamedChildren() {
				if isZeroLiteralNode(c) {
					continue
				}
				if name := bareOperandVar(c); name != "" {
					return []string{name}
				}
			}
		}
		if op == "*" {
			var vars []string
			for _, c := range cond.NamedChildren() {
				if name := bareOperandVar(c); name != "" {
					vars = append(vars, name)
				}
			}
			return vars
		}
	}
	return nil
}

// exitsEarly reports whether a statement block contains an early exit
// (return/continue/break/goto) that makes the guard a "skip on zero" guard.
func exitsEarly(stmt parser.Node) bool {
	for _, kind := range []string{"return_statement", "continue_statement", "break_statement", "goto_statement"} {
		if stmt.FindFirst(kind) != nil {
			return true
		}
	}
	return false
}

// backfillsToNonZero reports whether the consequence reassigns one of the
// guarded variables to a non-zero literal (`if (x == 0) x = 1;`), so the
// variable is non-zero after the if-statement regardless of the branch taken.
func backfillsToNonZero(consequence parser.Node, guarded []string) bool {
	guardedSet := make(map[string]bool, len(guarded))
	for _, g := range guarded {
		guardedSet[g] = true
	}
	for _, assign := range consequence.FindAll("assignment_expression") {
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs, rhs := children[0], children[1]
		if !guardedSet[bareOperandVar(lhs)] {
			continue
		}
		if !isZeroLiteralNode(rhs) {
			return true
		}
	}
	return false
}

// recordNonZeroAssignsAfter finds assignments `g = varName` or `g->field = varName`
// after line `afterLine` and records g/g->field as non-zero.
func recordNonZeroAssignsAfter(body parser.Node, afterLine int, varName string, inv *globalInvariants) {
	for _, assign := range body.FindAll("assignment_expression") {
		if assign.StartLine() <= afterLine {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs, rhs := children[0], children[1]
		if bareOperandVar(rhs) != varName {
			continue
		}
		target := assignTargetText(lhs)
		if target != "" {
			inv.nonZeroVars[target] = true
		}
	}
}

func assignTargetText(lhs parser.Node) string {
	for lhs.Kind() == "parenthesized_expression" {
		ch := lhs.NamedChildren()
		if len(ch) == 0 {
			return ""
		}
		lhs = ch[0]
	}
	switch lhs.Kind() {
	case "identifier", "field_expression":
		return lhs.Text()
	}
	return ""
}

// NonZero reports whether a global variable or field is proven non-zero by a
// cross-function invariant.
func (inv *globalInvariants) NonZero(name string) bool {
	return inv.nonZeroVars[strings.TrimSpace(name)]
}
func bareOperandVar(n parser.Node) string {
	for n.Kind() == "parenthesized_expression" {
		ch := n.NamedChildren()
		if len(ch) == 0 {
			return ""
		}
		n = ch[0]
	}
	if n.Kind() == "identifier" {
		return n.Text()
	}
	return ""
}

func isZeroLiteralNode(n parser.Node) bool {
	if n.Kind() != "number_literal" {
		return false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(n.Text()), 0, 64)
	return err == nil && v == 0
}
