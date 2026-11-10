package planner

import (
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// range_guard.go implements edge-level guard refinement for the interval
// engine (issue #253 P2-1). Before this, runRangeDataflow merged the SAME
// outgoing intervals into both successors of a condition, so `if (i >= MAX)
// continue;` never constrained i on the fall-through edge: a later `arr[i]`
// could be auto-confirmed OOB on a path the guard had already eliminated.
//
// A comparison guard (`i >= N`, `i < N`, `i == N`, ...) now tightens the
// variable's interval on each branch, and a branch whose interval becomes
// EMPTY (lo > hi) is unreachable — nothing is merged into it. That both
// removes the false confirmed verdict and keeps the analysis conservative:
// any condition shape the extractor does not understand falls back to the
// old unconditioned merge.

// guardCond is one extracted comparison `name op val` (val already folded).
type guardCond struct {
	name string
	op   string
	val  int64
	ok   bool
}

// extractGuardCond parses the condition of an if/while/for/do header into a
// comparison between one identifier and one constant. The constant may be a
// folded literal expression or another identifier whose incoming interval is
// already a singleton (a const local); anything else yields ok=false.
func extractGuardCond(n *graph.StmtNode, in map[string]interval) guardCond {
	if n == nil || n.Kind != "stmt" {
		return guardCond{}
	}
	var condPtr *parser.Node
	switch n.Stmt.Kind() {
	case "if_statement", "while_statement", "for_statement", "do_statement":
		condPtr = n.Stmt.ChildByFieldName("condition")
	default:
		return guardCond{}
	}
	if condPtr == nil {
		return guardCond{}
	}
	cond := *condPtr
	for cond.Kind() == "parenthesized_expression" {
		ch := cond.NamedChildren()
		if len(ch) == 0 {
			return guardCond{}
		}
		cond = ch[0]
	}
	if cond.Kind() != "binary_expression" {
		return guardCond{}
	}
	op := binaryOperatorToken(cond)
	switch op {
	case "<", "<=", ">", ">=", "==", "!=":
	default:
		return guardCond{}
	}
	children := cond.NamedChildren()
	if len(children) != 2 {
		return guardCond{}
	}
	lhs, rhs := children[0], children[1]
	if name, ok := guardIdent(lhs); ok {
		if v, vok := guardConst(rhs, in); vok {
			return guardCond{name: name, op: op, val: v, ok: true}
		}
	}
	if name, ok := guardIdent(rhs); ok {
		if v, vok := guardConst(lhs, in); vok {
			return guardCond{name: name, op: mirrorGuardOp(op), val: v, ok: true}
		}
	}
	return guardCond{}
}

// guardIdent unwraps parentheses/casts and returns the bare identifier name.
func guardIdent(n parser.Node) (string, bool) {
	for n.Kind() == "parenthesized_expression" || n.Kind() == "cast_expression" {
		ch := n.NamedChildren()
		if len(ch) == 0 {
			return "", false
		}
		n = ch[0]
	}
	if n.Kind() != "identifier" {
		return "", false
	}
	return n.Text(), true
}

// guardConst resolves a guard operand to a constant: a folded literal
// expression, or an identifier whose incoming interval is a singleton.
func guardConst(n parser.Node, in map[string]interval) (int64, bool) {
	if v, ok := foldConstExpr(n); ok {
		return v, true
	}
	if name, ok := guardIdent(n); ok {
		if r, exists := in[name]; exists && r.lo == r.hi {
			return r.lo, true
		}
	}
	return 0, false
}

func mirrorGuardOp(op string) string {
	switch op {
	case "<":
		return ">"
	case "<=":
		return ">="
	case ">":
		return "<"
	case ">=":
		return "<="
	default:
		return op
	}
}

func negateGuardOp(op string) string {
	switch op {
	case "<":
		return ">="
	case "<=":
		return ">"
	case ">":
		return "<="
	case ">=":
		return "<"
	case "==":
		return "!="
	case "!=":
		return "=="
	default:
		return op
	}
}

// refineForGuard applies the guard to the outgoing intervals on ONE branch.
// The second return value is false when the branch is unreachable (the
// refined interval is empty), in which case nothing must be merged into it.
func refineForGuard(out map[string]interval, g guardCond, branchTrue bool) (map[string]interval, bool) {
	op := g.op
	if !branchTrue {
		op = negateGuardOp(op)
	}
	r, ok := out[g.name]
	if !ok {
		r = topInterval()
	}
	switch op {
	case "<":
		r.hi = minInt64(r.hi, g.val-1)
	case "<=":
		r.hi = minInt64(r.hi, g.val)
	case ">":
		r.lo = maxInt64(r.lo, g.val+1)
	case ">=":
		r.lo = maxInt64(r.lo, g.val)
	case "==":
		r.lo = maxInt64(r.lo, g.val)
		r.hi = minInt64(r.hi, g.val)
	case "!=":
		// A single point cannot be subtracted from a closed interval; only the
		// exact-singleton case proves the branch unreachable.
		if r.lo == g.val && r.hi == g.val {
			return nil, false
		}
		return out, true
	}
	if r.lo > r.hi {
		return nil, false
	}
	refined := make(map[string]interval, len(out)+1)
	for v, iv := range out {
		refined[v] = iv
	}
	refined[g.name] = r
	return refined, true
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
