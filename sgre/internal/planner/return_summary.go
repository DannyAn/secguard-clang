package planner

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// returnSummaryResolver lazily computes, per function, whether every return
// statement yields a provably non-zero integer. It powers the divide-by-zero
// convergence: a divisor that is a call result (`x / get_count()`) or a local
// seeded from one (`int d = get_count(); x / d`) is suppressed when the callee
// provably never returns zero. This is the interprocedural interval-summary step
// that covers `idm_get_worker_num()`-style divisors the function-local
// range_flow.go interval alone cannot see.
//
// It is conservative in the one direction that matters: only "every return is
// non-zero" resolves to safe. Any undeterminable return (a parameter, a global, a
// compound arithmetic expression, another unresolved call, a void return) drops
// the whole function to "unknown", so a real divide-by-zero is never suppressed
// by an imprecise summary.
type returnSummaryResolver struct {
	store  db.Store
	parser *parser.Parser
	cache  *fileParseCache

	funcByName map[string][]int64
	fnByID     map[int64]*db.Function
	fileByID   map[int64]*db.File

	memo     map[int64]bool
	visiting map[int64]bool
}

func newReturnSummaryResolver(ctx context.Context, store db.Store, p *parser.Parser) *returnSummaryResolver {
	r := &returnSummaryResolver{
		store:      store,
		parser:     p,
		cache:      newFileParseCache(p),
		funcByName: map[string][]int64{},
		fnByID:     map[int64]*db.Function{},
		fileByID:   map[int64]*db.File{},
		memo:       map[int64]bool{},
		visiting:   map[int64]bool{},
	}
	if funcs, err := store.ListFunctions(ctx); err == nil {
		for _, fn := range funcs {
			r.funcByName[fn.Name] = append(r.funcByName[fn.Name], fn.ID)
			r.fnByID[fn.ID] = fn
		}
	}
	r.fileByID = listFilesByID(ctx, store)
	return r
}

// callResult implements the buildRangeEffects callResult resolver callback: it
// returns the interval of `name()`'s return value when that value is provably
// non-zero, else (interval{}, false).
func (r *returnSummaryResolver) callResult(name string) (interval, bool) {
	if r.nonZeroReturn(name) {
		return interval{1, rMax}, true
	}
	return interval{}, false
}

// nonZeroReturn reports whether calling `name` yields a provably non-zero value,
// either via the apikb library-contract table or by summarizing every local
// definition of name.
func (r *returnSummaryResolver) nonZeroReturn(name string) bool {
	if apikb.NonZeroReturn(name) {
		return true
	}
	ids := r.funcByName[name]
	if len(ids) == 0 {
		return false
	}
	for _, fid := range ids {
		if !r.funcNonZero(fid) {
			return false
		}
	}
	return true
}

// funcNonZero reports whether every return statement in fn yields a non-zero
// integer. Memoized and cycle-guarded: unresolved dependencies resolve to false.
func (r *returnSummaryResolver) funcNonZero(fnID int64) bool {
	if v, ok := r.memo[fnID]; ok {
		return v
	}
	if r.visiting[fnID] {
		return false
	}
	r.visiting[fnID] = true
	defer delete(r.visiting, fnID)

	fn := r.fnByID[fnID]
	if fn == nil {
		r.memo[fnID] = false
		return false
	}
	file := r.fileByID[fn.FileID]
	if file == nil {
		r.memo[fnID] = false
		return false
	}
	body, root := r.cache.get(file, fn)
	if body.Kind() != "compound_statement" {
		r.memo[fnID] = false
		return false
	}

	flow := analyzeRanges(fn, body)
	consts := parser.CollectConstantSymbols(root)
	returns := body.FindAll("return_statement")
	if len(returns) == 0 {
		r.memo[fnID] = false
		return false
	}
	for _, ret := range returns {
		expr := returnExpr(ret)
		if expr == nil {
			r.memo[fnID] = false
			return false
		}
		if iv, ok := r.exprInterval(*expr, flow, consts); !ok || !iv.isNonZero() {
			r.memo[fnID] = false
			return false
		}
	}
	r.memo[fnID] = true
	return true
}

// exprInterval computes the integer interval of a return expression, or
// (interval{}, false) when it cannot be determined (which the caller treats as
// "possibly zero"). It recognizes literals, sizeof, compile-time constant names,
// in-function variable ranges, parentheses/casts, and nested non-zero-returning
// calls.
func (r *returnSummaryResolver) exprInterval(expr parser.Node, flow *rangeFlow, consts *parser.ConstantEnv) (interval, bool) {
	switch expr.Kind() {
	case "number_literal":
		return literalInterval(expr.Text())
	case "sizeof_expression":
		return interval{1, rMax}, true
	case "identifier":
		if consts.NonZero(expr.Text()) {
			return interval{1, rMax}, true
		}
		if flow != nil {
			return flow.at(expr.Text(), expr.StartLine()), true
		}
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if iv, ok := r.exprInterval(c, flow, consts); ok {
				return iv, true
			}
		}
	case "unary_expression":
		return literalInterval(expr.Text())
	case "call_expression":
		if name := callName(expr); name != "" && r.nonZeroReturn(name) {
			return interval{1, rMax}, true
		}
	}
	return interval{}, false
}

// returnExpr returns the single expression node a return_statement returns, or
// nil for a bare `return;`.
func returnExpr(ret parser.Node) *parser.Node {
	named := ret.NamedChildren()
	if len(named) == 0 {
		return nil
	}
	return &named[0]
}

// literalInterval parses a signed integer literal (decimal/hex/octal, with C
// suffixes) into a constant interval.
func literalInterval(text string) (interval, bool) {
	s := strings.TrimSpace(text)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = strings.TrimSpace(s[1:])
	} else if strings.HasPrefix(s, "+") {
		s = strings.TrimSpace(s[1:])
	}
	s = strings.TrimRight(s, "uUlL")
	if s == "" {
		return interval{}, false
	}
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return interval{}, false
	}
	if neg {
		v = -v
	}
	return constInterval(v), true
}
