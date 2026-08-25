package evidence

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// RangeFacts holds lightweight variable bounds derived from if-statement
// guards within a single function. It is a line-approximation of an interval
// domain — not a full abstract interpretation — sufficient to suppress
// candidates whose operands are provably bounded or non-zero on the reaching
// path.
type RangeFacts struct {
	// nonZeroAfter maps a variable to the line numbers after which it is
	// non-zero, established by an early-return guard (`if (x == 0) return;`
	// → x != 0 on the fall-through, i.e. at lines > if.EndLine).
	nonZeroAfter map[string][]int
	// nonZeroInside maps a variable to [start, end] line ranges where it is
	// non-zero, established by a positive guard (`if (x != 0) { ... }`).
	nonZeroInside map[string][][2]int
	// hiInside maps a variable to ranges+bounds where it has an upper bound,
	// established by `if (x < N)` / `if (x <= N)`.
	hiInside map[string][]hiRange
	// reassigns maps a variable to its whole-variable reassignment sites (line
	// + RHS text). A reassignment invalidates a guard-derived fact: NonZeroAt
	// kills on a possibly-zero RHS, UpperBoundAt on any reassignment.
	reassigns map[string][]reassignSite
}

type hiRange struct {
	start, end, hi int
}

// reassignSite is one whole-variable reassignment site.
type reassignSite struct {
	line int
	rhs  string
}

var (
	reLt     = regexp.MustCompile(`^(\w+)\s*<\s*(\d+)$`)
	reLe     = regexp.MustCompile(`^(\w+)\s*<=\s*(\d+)$`)
	reGt     = regexp.MustCompile(`^(\w+)\s*>\s*(\d+)$`)
	reGe     = regexp.MustCompile(`^(\w+)\s*>=\s*(\d+)$`)
	reNeZero = regexp.MustCompile(`^(\w+)\s*!=\s*0$`)
	reEqZero = regexp.MustCompile(`^(\w+)\s*==\s*0$`)
	reNot    = regexp.MustCompile(`^!(\w+)$`)
	reBare   = regexp.MustCompile(`^(\w+)$`)
	reNeNull = regexp.MustCompile(`^(\w+)\s*!=\s*NULL$`)
	reEqNull = regexp.MustCompile(`^(\w+)\s*==\s*NULL$`)
)

// IfsInFunc returns the if-statements whose line range falls within [start,
// end], so AnalyzeBounds only sees guards from the same function and cannot
// leak a non-zero fact (e.g. open_handle's `if (!h) return`) into a different
// function that happens to dereference a same-named variable at a later line.
func IfsInFunc(ifs []parser.Node, start, end int) []parser.Node {
	var out []parser.Node
	for _, ifStmt := range ifs {
		if ifStmt.StartLine() >= start && ifStmt.EndLine() <= end {
			out = append(out, ifStmt)
		}
	}
	return out
}

// assignsInFunc returns the assignment_expression nodes whose start line falls
// within [start, end], so AnalyzeBounds only sees reassignments from the same
// function (mirrors IfsInFunc, which scopes the guards).
func assignsInFunc(assigns []parser.Node, start, end int) []parser.Node {
	var out []parser.Node
	for _, assign := range assigns {
		if assign.StartLine() >= start && assign.StartLine() <= end {
			out = append(out, assign)
		}
	}
	return out
}

// AnalyzeBounds scans if-statement conditions and records the variable bounds
// they establish. It recognizes:
//   - `if (x < N)` / `if (x <= N)`: x bounded above inside the body.
//   - `if (x > N)` / `if (x >= N)`: x non-zero inside the body when N >= 0.
//   - `if (x != 0)` / `if (x)` / `if (x != NULL)`: x non-zero inside the body.
//   - `if (x == 0) return` / `if (!x) return` / `if (x == NULL) return`:
//     x non-zero after the if (fall-through).
func AnalyzeBounds(ifs, assigns []parser.Node) *RangeFacts {
	r := &RangeFacts{
		nonZeroAfter:  make(map[string][]int),
		nonZeroInside: make(map[string][][2]int),
		hiInside:      make(map[string][]hiRange),
		reassigns:     make(map[string][]reassignSite),
	}
	for _, assign := range assigns {
		children := assign.NamedChildren()
		if len(children) < 2 || children[0].Kind() != "identifier" {
			continue
		}
		r.reassigns[children[0].Text()] = append(r.reassigns[children[0].Text()], reassignSite{line: assign.StartLine(), rhs: children[1].Text()})
	}
	for _, ifStmt := range ifs {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		ct := stripParens(strings.TrimSpace(cond.Text()))
		start, end := ifStmt.StartLine(), ifStmt.EndLine()
		cons := ifStmt.ChildByFieldName("consequence")
		exits := cons != nil && isExitStmt(*cons)

		if m := reLt.FindStringSubmatch(ct); m != nil {
			if n, err := strconv.Atoi(m[2]); err == nil {
				r.hiInside[m[1]] = append(r.hiInside[m[1]], hiRange{start, end, n - 1})
			}
			continue
		}
		if m := reLe.FindStringSubmatch(ct); m != nil {
			if n, err := strconv.Atoi(m[2]); err == nil {
				r.hiInside[m[1]] = append(r.hiInside[m[1]], hiRange{start, end, n})
			}
			continue
		}
		if m := reGt.FindStringSubmatch(ct); m != nil {
			if n, err := strconv.Atoi(m[2]); err == nil && n >= 0 {
				r.nonZeroInside[m[1]] = append(r.nonZeroInside[m[1]], [2]int{start, end})
			}
			continue
		}
		if m := reGe.FindStringSubmatch(ct); m != nil {
			if n, err := strconv.Atoi(m[2]); err == nil && n >= 1 {
				r.nonZeroInside[m[1]] = append(r.nonZeroInside[m[1]], [2]int{start, end})
			}
			continue
		}
		if m := reNeZero.FindStringSubmatch(ct); m != nil {
			r.nonZeroInside[m[1]] = append(r.nonZeroInside[m[1]], [2]int{start, end})
			continue
		}
		if m := reNeNull.FindStringSubmatch(ct); m != nil {
			r.nonZeroInside[m[1]] = append(r.nonZeroInside[m[1]], [2]int{start, end})
			continue
		}
		if m := reBare.FindStringSubmatch(ct); m != nil {
			r.nonZeroInside[m[1]] = append(r.nonZeroInside[m[1]], [2]int{start, end})
			continue
		}
		// Reassignment guard: `if (x == 0) x = <nonzero>;` / `if (!x) x = 1;`
		// leaves x non-zero on the fall-through as well (the then-branch assigns
		// a non-zero literal, every other path already had x != 0). Equivalent to
		// the early-return guard for non-zero-ness.
		if cons != nil {
			if m := reEqZero.FindStringSubmatch(ct); m != nil && consequenceAssignsNonZero(*cons, m[1]) {
				r.nonZeroAfter[m[1]] = append(r.nonZeroAfter[m[1]], end)
				continue
			}
			if m := reNot.FindStringSubmatch(ct); m != nil && consequenceAssignsNonZero(*cons, m[1]) {
				r.nonZeroAfter[m[1]] = append(r.nonZeroAfter[m[1]], end)
				continue
			}
		}
		// Fall-through non-zero: the guard exits when the condition is true,
		// so the continuation establishes the negation.
		if exits {
			if m := reEqZero.FindStringSubmatch(ct); m != nil {
				r.nonZeroAfter[m[1]] = append(r.nonZeroAfter[m[1]], end)
				continue
			}
			if m := reEqNull.FindStringSubmatch(ct); m != nil {
				r.nonZeroAfter[m[1]] = append(r.nonZeroAfter[m[1]], end)
				continue
			}
			if m := reNot.FindStringSubmatch(ct); m != nil {
				r.nonZeroAfter[m[1]] = append(r.nonZeroAfter[m[1]], end)
				continue
			}
		}
	}
	return r
}

// consequenceAssignsNonZero reports whether an if-consequence body assigns the
// given variable a non-zero value (a non-zero literal or sizeof), e.g. the
// `x = 1` in `if (x == 0) x = 1;`. Such an assignment makes x non-zero on every
// path that falls through the guard.
func consequenceAssignsNonZero(node parser.Node, varName string) bool {
	for _, assign := range node.FindAll("assignment_expression") {
		named := assign.NamedChildren()
		if len(named) < 2 || strings.TrimSpace(named[0].Text()) != varName {
			continue
		}
		if !possiblyZeroDivisor(named[1].Text()) {
			return true
		}
	}
	return false
}

// NonZeroAt reports whether var is established non-zero at the given line,
// either by a positive guard whose body contains the line, or by an
// early-return guard whose fall-through precedes the line. A whole-variable
// reassignment between the guard and the line kills the fact.
func (r *RangeFacts) NonZeroAt(v string, line int) bool {
	for _, rng := range r.nonZeroInside[v] {
		if line >= rng[0] && line <= rng[1] && !r.reassignedToPossiblyZeroIn(v, rng[0], line) {
			return true
		}
	}
	for _, after := range r.nonZeroAfter[v] {
		if line > after && !r.reassignedToPossiblyZeroIn(v, after+1, line) {
			return true
		}
	}
	return false
}

// reassignedToPossiblyZeroIn reports whether v is whole-variable reassigned to a
// possibly-zero RHS at any line in [start, end]. A possibly-zero RHS kills a
// non-zero fact; `v = 5` re-establishes non-zero and does not.
func (r *RangeFacts) reassignedToPossiblyZeroIn(v string, start, end int) bool {
	for _, s := range r.reassigns[v] {
		if s.line >= start && s.line <= end && possiblyZeroDivisor(s.rhs) {
			return true
		}
	}
	return false
}

// reassignedIn reports whether v is whole-variable reassigned at any line in
// [start, end], regardless of the RHS.
func (r *RangeFacts) reassignedIn(v string, start, end int) bool {
	for _, s := range r.reassigns[v] {
		if s.line >= start && s.line <= end {
			return true
		}
	}
	return false
}

// UpperBoundAt returns the tightest proven upper bound for var at the given
// line (inside a `if (x < N)` body), or 0 if none is known.
func (r *RangeFacts) UpperBoundAt(v string, line int) int {
	best := 0
	for _, hr := range r.hiInside[v] {
		if line >= hr.start && line <= hr.end {
			// A reassignment inside the guard body invalidates the bound
			// (`if (n < cap) { n = 1000; memcpy(..., n); }` — n is no longer < cap).
			if r.reassignedIn(v, hr.start, line) {
				continue
			}
			if best == 0 || hr.hi < best {
				best = hr.hi
			}
		}
	}
	return best
}

// stripParens removes a single layer of surrounding parentheses from a
// condition text so `(x < N)` matches the same patterns as `x < N`.
func stripParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		inner := s[1 : len(s)-1]
		if balanced(inner) {
			s = strings.TrimSpace(inner)
		} else {
			break
		}
	}
	return s
}

func balanced(s string) bool {
	depth := 0
	for _, c := range s {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}
