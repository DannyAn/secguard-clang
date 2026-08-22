package planner

import (
	"strconv"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// range_flow.go implements a forward integer-interval analysis over the
// statement CFG. Unlike the detector-side range_analysis.go (a line-approximation
// of if-guards), this engine propagates intervals ACROSS assignments: `d = 0;
// d = 1;` yields d ∈ [1,1] at the later division, which a line-scan cannot see.
//
// The lattice is a closed interval [lo, hi] (the full range is the top), and the
// join is the hull (union), which is the conservative direction for proving a
// variable is non-zero or bounded: if the over-approximating hull is safe, every
// concrete value is safe.

const (
	rMin = -1 << 63
	rMax = 1<<63 - 1
)

// interval is a closed integer bound [lo, hi].
type interval struct {
	lo, hi int64
}

func topInterval() interval          { return interval{rMin, rMax} }
func constInterval(c int64) interval { return interval{c, c} }

// join returns the hull of r and o (the over-approximation of both).
func (r interval) join(o interval) interval {
	lo, hi := r.lo, r.hi
	if o.lo < lo {
		lo = o.lo
	}
	if o.hi > hi {
		hi = o.hi
	}
	return interval{lo, hi}
}

// isNonZero reports whether every value in the interval is non-zero.
func (r interval) isNonZero() bool {
	return r.lo > 0 || r.hi < 0
}

// shift adds delta to both bounds, saturating at rMin/rMax so a loop counter
// (`i++`) cannot wrap past the extremes and oscillate.
func (r interval) shift(delta int64) interval {
	lo, hi := r.lo, r.hi
	if delta >= 0 {
		if lo > rMax-delta {
			lo = rMax
		} else {
			lo += delta
		}
		if hi > rMax-delta {
			hi = rMax
		} else {
			hi += delta
		}
	} else {
		if lo < rMin-delta {
			lo = rMin
		} else {
			lo += delta
		}
		if hi < rMin-delta {
			hi = rMin
		} else {
			hi += delta
		}
	}
	return interval{lo, hi}
}

// shiftEffect is one `n = m + c` / `n = m - c` / `n++` / `n--` effect.
type shiftEffect struct {
	base  string
	delta int64
}

// rangeEffects are the per-node transfer effects for the interval analysis.
type rangeEffects struct {
	assign map[string]interval
	copy   map[string]string
	shift  map[string]shiftEffect
	kill   map[string]bool
}

// rangeFlow is the per-function interval-analysis result, queryable by
// (variable, line).
type rangeFlow struct {
	cfg    *graph.StmtCFG
	nodeIn map[int]map[string]interval
}

// at returns the interval for variable at line, or the full range when unknown.
func (f *rangeFlow) at(variable string, line int) interval {
	if f == nil || f.cfg == nil {
		return topInterval()
	}
	n := f.cfg.NodeAt(line)
	if n == nil {
		return topInterval()
	}
	if r, ok := f.nodeIn[n.ID][variable]; ok {
		return r
	}
	return topInterval()
}

// analyzeRanges builds and runs the interval analysis for one function body.
func analyzeRanges(fn *db.Function, body parser.Node) *rangeFlow {
	if body.Kind() != "compound_statement" {
		return nil
	}
	cfg := graph.BuildStmtCFG(body, fn.EndLine)
	return &rangeFlow{cfg: cfg, nodeIn: runRangeDataflow(cfg, buildRangeEffects(cfg))}
}

// buildRangeEffects extracts the per-node assignment/update transfer effects.
func buildRangeEffects(cfg *graph.StmtCFG) map[int]*rangeEffects {
	effects := make(map[int]*rangeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		e := &rangeEffects{
			assign: map[string]interval{},
			copy:   map[string]string{},
			shift:  map[string]shiftEffect{},
			kill:   map[string]bool{},
		}
		for _, p := range directAssignments(n.Stmt) {
			name := assignTargetName(p.lhs)
			if name == "" {
				continue
			}
			if c, ok := constFromExpr(p.rhs); ok {
				e.assign[name] = c
			} else if base, delta, ok := shiftFromExpr(p.rhs); ok {
				e.shift[name] = shiftEffect{base: base, delta: delta}
			} else if k := copySourceKey(p.rhs); k != "" {
				e.copy[name] = k
			} else {
				e.kill[name] = true
			}
		}
		// `n++` / `n--` / `++n` / `--n` shift the variable by ±1.
		for _, upd := range n.Stmt.FindAll("update_expression") {
			if name, delta, ok := updateShift(upd); ok {
				e.shift[name] = shiftEffect{base: name, delta: delta}
			}
		}
		effects[n.ID] = e
	}
	return effects
}

// constFromExpr returns the constant interval when expr is a numeric literal
// (possibly wrapped in a cast/parentheses).
func constFromExpr(n parser.Node) (interval, bool) {
	switch n.Kind() {
	case "number_literal":
		if v, err := strconv.ParseInt(n.Text(), 0, 64); err == nil {
			return constInterval(v), true
		}
	case "parenthesized_expression", "cast_expression":
		for _, c := range n.NamedChildren() {
			if r, ok := constFromExpr(c); ok {
				return r, true
			}
		}
	}
	return interval{}, false
}

// shiftFromExpr returns (base, delta) when expr is `m + c`, `c + m`, or `m - c`
// for a numeric literal c; a `c - m` shape is not a simple shift and returns ok
// = false.
func shiftFromExpr(n parser.Node) (string, int64, bool) {
	if n.Kind() != "binary_expression" {
		return "", 0, false
	}
	named := n.NamedChildren()
	if len(named) < 2 {
		return "", 0, false
	}
	lhs, rhs := named[0], named[1]
	op := ""
	for _, c := range n.Children() {
		switch c.Kind() {
		case "+", "-":
			op = c.Kind()
		}
	}
	if op == "" {
		return "", 0, false
	}
	var base string
	var constVal int64
	switch {
	case lhs.Kind() == "identifier" && rhs.Kind() == "number_literal":
		v, err := strconv.ParseInt(rhs.Text(), 0, 64)
		if err != nil {
			return "", 0, false
		}
		base, constVal = lhs.Text(), v
	case lhs.Kind() == "number_literal" && rhs.Kind() == "identifier" && op == "+":
		v, err := strconv.ParseInt(lhs.Text(), 0, 64)
		if err != nil {
			return "", 0, false
		}
		base, constVal = rhs.Text(), v
	default:
		return "", 0, false
	}
	if op == "-" {
		constVal = -constVal
	}
	return base, constVal, true
}

// updateShift returns (variable, ±1) for an update_expression `n++` / `n--` /
// `++n` / `--n`.
func updateShift(n parser.Node) (string, int64, bool) {
	if n.Kind() != "update_expression" {
		return "", 0, false
	}
	name := ""
	delta := int64(0)
	for _, c := range n.Children() {
		switch c.Kind() {
		case "++":
			delta = 1
		case "--":
			delta = -1
		case "identifier":
			name = c.Text()
		}
	}
	if name == "" {
		return "", 0, false
	}
	return name, delta, true
}

// runRangeDataflow runs the forward interval analysis with a hull (union) join
// and WIDENING. A loop counter (`for (i=0; i<n; i++)`) would otherwise widen its
// interval one unit per back-edge pass and never reach the fixpoint; after a few
// growths at the same program point the moving bound is widened to ±inf, which is
// the safe over-approximation for the "prove safe" consumers.
func runRangeDataflow(cfg *graph.StmtCFG, effects map[int]*rangeEffects) map[int]map[string]interval {
	nodeIn := make(map[int]map[string]interval, len(cfg.Nodes))
	widenCount := make(map[int]map[string]int, len(cfg.Nodes))
	for i := range cfg.Nodes {
		nodeIn[i] = map[string]interval{}
		widenCount[i] = map[string]int{}
	}

	// Seed the worklist with every node, not just the entry: a node with an
	// assignment effect (`d = 0`, `d = 1`) introduces a fact regardless of its
	// input, so it must be visited even when its predecessor contributes nothing.
	worklist := make([]int, 0, len(cfg.Nodes))
	inQueue := make([]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		worklist = append(worklist, i)
		inQueue[i] = true
	}

	for len(worklist) > 0 {
		id := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		inQueue[id] = false

		out := rangeTransfer(nodeIn[id], effects[id])
		for _, succ := range cfg.Nodes[id].Succs {
			if rangeMergeInto(nodeIn[succ], widenCount[succ], out) && !inQueue[succ] {
				inQueue[succ] = true
				worklist = append(worklist, succ)
			}
		}
	}
	return nodeIn
}

func rangeTransfer(in map[string]interval, e *rangeEffects) map[string]interval {
	out := make(map[string]interval, len(in)+4)
	for v, r := range in {
		out[v] = r
	}
	if e == nil {
		return out
	}
	for v, r := range e.assign {
		out[v] = r
	}
	for v, k := range e.copy {
		out[v] = in[k]
	}
	for v, s := range e.shift {
		out[v] = in[s.base].shift(s.delta)
	}
	for v := range e.kill {
		out[v] = topInterval()
	}
	return out
}

// widenDelay is how many times a bound may grow at one program point before the
// widening operator sends it to ±inf. Enough to settle constant assignments and
// small shifts, few enough that a loop counter converges in O(nodes) passes.
const widenDelay = 3

// rangeMergeInto hull-joins src into dst in place, widening a bound to ±inf once
// it has grown widenDelay times at the same program point. It reports whether dst
// changed.
func rangeMergeInto(dst map[string]interval, counts map[string]int, src map[string]interval) bool {
	changed := false
	for v, r := range src {
		prev, ok := dst[v]
		if !ok {
			dst[v] = r
			changed = true
			continue
		}
		joined := prev.join(r)
		if joined == prev {
			continue
		}
		if counts[v] >= widenDelay {
			if joined.lo < prev.lo {
				joined.lo = rMin
			}
			if joined.hi > prev.hi {
				joined.hi = rMax
			}
		}
		counts[v]++
		dst[v] = joined
		changed = true
	}
	return changed
}
