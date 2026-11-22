package planner

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// runDataflow runs the forward null-source reaching analysis. IN[entry] is
// empty (no variable is known null at function entry, matching the event-based
// source model), joins are unions of source-ID sets, and the transfer applies
// copy, kill, then gen. The lattice is monotone (source sets only grow at
// joins; a kill replaces a variable's set with the empty set, which is a fixed
// set-difference under union), so iteration order does not affect the fixpoint.
func runDataflow(cfg *graph.StmtCFG, effects map[int]*nodeEffects, entrySeeds map[string]bool, guard *guardModel) map[int]map[string]map[int]bool {
	nodeIn := make(map[int]map[string]map[int]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		nodeIn[i] = map[string]map[int]bool{}
	}

	// Seed the entry's IN with caller-influenced variables (function parameters
	// proven tainted by some caller). This makes the callee's intra-procedural
	// flow carry the inter-procedural context, so a sink on a LOCAL derived from
	// a tainted parameter is no longer a false negative.
	if len(entrySeeds) > 0 {
		for v := range entrySeeds {
			nodeIn[cfg.Entry][v] = map[int]bool{cfg.Entry: true}
		}
	}

	// Seed the worklist with every node, not just the entry: a node with a gen
	// effect adds facts regardless of its input, so it must be visited even
	// when its predecessor contributes nothing.
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

		out := transfer(nodeIn[id], effects[id], id)
		for _, succ := range cfg.Nodes[id].Succs {
			o := out
			if guard != nil {
				if gk := guard.edgeKills[[2]int{id, succ}]; len(gk) > 0 {
					// A guard kills a variable's null source only on this edge, so
					// clone the shared OUT before mutating it.
					o = make(map[string]map[int]bool, len(out))
					for v, srcs := range out {
						o[v] = srcs
					}
					for v := range gk {
						o[v] = map[int]bool{}
					}
				}
			}
			if mergeInto(nodeIn[succ], o) && !inQueue[succ] {
				inQueue[succ] = true
				worklist = append(worklist, succ)
			}
		}
	}
	return nodeIn
}

// transfer computes OUT = gen ∪ copy(in) ∪ (in \ kill), where in/out are
// source-ID sets keyed by variable and each gen source is identified by nodeID.
func transfer(in map[string]map[int]bool, e *nodeEffects, nodeID int) map[string]map[int]bool {
	out := make(map[string]map[int]bool, len(in)+4)
	for v, srcs := range in {
		out[v] = cloneSet(srcs)
	}
	if e == nil {
		return out
	}
	for lhs, rhs := range e.copy {
		out[lhs] = cloneSet(in[rhs])
	}
	for lhs, base := range e.copyFieldBase {
		if out[lhs] == nil {
			out[lhs] = map[int]bool{}
		}
		for s := range in[base] {
			out[lhs][s] = true
		}
	}
	for v := range e.kill {
		out[v] = map[int]bool{}
	}
	for base := range e.killBase {
		for k := range out {
			if isFieldOf(k, base) {
				out[k] = map[int]bool{}
			}
		}
	}
	for v := range e.gen {
		if out[v] == nil {
			out[v] = map[int]bool{}
		}
		out[v][nodeID] = true
	}
	return out
}

// isFieldOf reports whether key k names a field or element of base (p->f,
// p.f, or p[i]), which a whole-variable reassignment of base invalidates.
func isFieldOf(k, base string) bool {
	return strings.HasPrefix(k, base+"->") || strings.HasPrefix(k, base+".") || strings.HasPrefix(k, base+"[")
}

// mergeInto unions src into dst in place (per-variable source-set union) and
// reports whether dst changed.
func mergeInto(dst, src map[string]map[int]bool) bool {
	changed := false
	for v, srcs := range src {
		if len(srcs) == 0 {
			continue
		}
		if dst[v] == nil {
			dst[v] = map[int]bool{}
		}
		for s := range srcs {
			if !dst[v][s] {
				dst[v][s] = true
				changed = true
			}
		}
	}
	return changed
}

// runMustDataflow runs a forward BOOLEAN must analysis over the same CFG/effects
// shape as runDataflow. Unlike the may tier (union join, bottom = empty), the
// must tier joins with INTERSECTION and initializes non-entry nodes to TOP (the
// universe of variables that can ever hold the fact), so a fact survives only
// when every incoming path carries it. A kill on one branch therefore clears the
// fact at the join, which is exactly the semantics "certainly null" / "certainly
// freed" / "certainly uninitialized" require.
func runMustDataflow(cfg *graph.StmtCFG, effects map[int]*nodeEffects, entrySeeds map[string]bool) (map[int]map[string]bool, map[int]map[string]bool) {
	// universe: every variable that appears in any effect (gen/kill/copy target
	// or source). TOP for a variable is "true on every path so far". Entry seeds
	// are added so a parameter proven null by a caller is tracked even when the
	// callee body has no assignment of it.
	universe := make(map[string]bool)
	for _, e := range effects {
		if e == nil {
			continue
		}
		for v := range e.gen {
			universe[v] = true
		}
		for v := range e.kill {
			universe[v] = true
		}
		for lhs, rhs := range e.copy {
			universe[lhs] = true
			universe[rhs] = true
		}
	}
	for v := range entrySeeds {
		universe[v] = true
	}

	nodeIn := make(map[int]map[string]bool, len(cfg.Nodes))
	for i := range cfg.Nodes {
		m := make(map[string]bool, len(universe))
		if i != cfg.Entry {
			for v := range universe {
				m[v] = true
			}
		} else {
			for v := range entrySeeds {
				m[v] = true
			}
		}
		nodeIn[i] = m
	}

	// Seed the worklist with EVERY node, not just the entry. A node with a gen
	// (`p = NULL`) or kill (`p = f()`) effect introduces a fact regardless of its
	// input, so it must be visited even when its predecessor contributes nothing;
	// and a control-flow header (if/while) with no own effect must still forward
	// its predecessor's fact to its branches — otherwise a kill inside the branch
	// is never reached and a reassignment after `p = NULL` fails to clear the
	// certain-null fact. This mirrors runRangeDataflow's seed-every-node.
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

		out := mustTransfer(nodeIn[id], effects[id])
		for _, succ := range cfg.Nodes[id].Succs {
			if mustMergeInto(nodeIn[succ], out) && !inQueue[succ] {
				inQueue[succ] = true
				worklist = append(worklist, succ)
			}
		}
	}

	genAt := make(map[int]map[string]bool)
	for id, e := range effects {
		if e != nil && len(e.gen) > 0 {
			m := make(map[string]bool, len(e.gen))
			for v := range e.gen {
				m[v] = true
			}
			genAt[id] = m
		}
	}
	return nodeIn, genAt
}

// mustTransfer computes OUT for a boolean must node: copy propagates the source's
// fact, kill clears it, gen sets it. Order is copy, then kill, then gen.
func mustTransfer(in map[string]bool, e *nodeEffects) map[string]bool {
	out := make(map[string]bool, len(in))
	for v, b := range in {
		out[v] = b
	}
	if e == nil {
		return out
	}
	for lhs, rhs := range e.copy {
		out[lhs] = in[rhs]
	}
	for v := range e.kill {
		out[v] = false
	}
	for base := range e.killBase {
		for k := range out {
			if isFieldOf(k, base) {
				out[k] = false
			}
		}
	}
	for v := range e.gen {
		out[v] = true
	}
	return out
}

// mustMergeInto intersects src into dst in place (boolean AND) and reports
// whether dst changed. A variable absent from src means false on that path.
func mustMergeInto(dst, src map[string]bool) bool {
	changed := false
	for v, b := range dst {
		if !b {
			continue // already false; AND with anything stays false
		}
		if !src[v] {
			dst[v] = false
			changed = true
		}
	}
	return changed
}

func cloneSet(src map[int]bool) map[int]bool {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[int]bool, len(src))
	for s := range src {
		dst[s] = true
	}
	return dst
}

func genAt(cfg *graph.StmtCFG, effects map[int]*nodeEffects) map[int]map[string]bool {
	genAt := make(map[int]map[string]bool, len(cfg.Nodes))
	for id, e := range effects {
		if e != nil && len(e.gen) > 0 {
			genAt[id] = e.gen
		}
	}
	return genAt
}

func buildWeakGuardMap(cfg *graph.StmtCFG) map[int]map[string]bool {
	out := make(map[int]map[string]bool)
	if cfg == nil {
		return out
	}
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" || !isConditionKind(n.Stmt.Kind()) {
			continue
		}
		cond := n.Stmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		for _, v := range parser.NullCheckedVars(*cond) {
			if out[n.ID] == nil {
				out[n.ID] = map[string]bool{}
			}
			out[n.ID][v] = true
		}
	}
	return out
}

// ternaryGuardEntry is one dereference point proven non-null by a conditional
// expression's guard: `p != NULL ? p->f : d` proves p non-null for the `p->f`
// dereference inside the consequence (true branch); `p == NULL ? d : p->f`
// proves it for the alternative (false branch). The entry records the exact
// dereference line, so a same-line `p == NULL ? p->a : 0` (the NULL-path
// dereference in the consequence) is NOT guarded by the alternative-side guard.
type ternaryGuardEntry struct {
	variable string
	line     int
}

// buildTernaryGuardMap collects the null-guarded dereference points of every
// conditional expression in a function body. A conditional expression stays
// inside one straight-line CFG node, so these guards cannot ride the edge-kill
// model; the guarded branch's own dereference sites are recorded from the AST
// (base-precise, line-precise) and resolved at the nullable-source convergence
// stage. Only dereferences whose BASE is exactly the guarded variable match:
// `p->a->b` contributes the inner `p->a` read (base p), which is what a guard
// on p protects.
func buildTernaryGuardMap(body parser.Node) []ternaryGuardEntry {
	if body.Kind() != "compound_statement" {
		return nil
	}
	var out []ternaryGuardEntry
	for _, ce := range body.FindAll("conditional_expression") {
		cond := ce.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if cons := ce.ChildByFieldName("consequence"); cons != nil {
			for _, v := range parser.GuardedNonnullVars(*cond) {
				out = append(out, guardedDerefEntries(*cons, v)...)
			}
		}
		if alt := ce.ChildByFieldName("alternative"); alt != nil {
			for _, v := range parser.NullCheckedVars(*cond) {
				out = append(out, guardedDerefEntries(*alt, v)...)
			}
		}
	}
	// Short-circuit guards: `p && p->x` evaluates p->x only when p is truthy,
	// and `p == NULL || p->x` evaluates p->x only when p != NULL. These are
	// binary_expression shapes (not conditional_expression), so they need their
	// own pass over the same base-precise, line-precise deref recording.
	for _, be := range body.FindAll("binary_expression") {
		op := parser.BinaryOperator(be)
		if op != "&&" && op != "||" {
			continue
		}
		children := be.NamedChildren()
		if len(children) < 2 {
			continue
		}
		left, right := children[0], children[1]
		if op == "&&" {
			for _, v := range parser.GuardedNonnullVars(left) {
				out = append(out, guardedDerefEntries(right, v)...)
			}
		} else {
			for _, v := range parser.NullCheckedVars(left) {
				out = append(out, guardedDerefEntries(right, v)...)
			}
		}
	}
	return out
}

// guardedDerefEntries finds branch's dereference points of variable: field
// accesses (`v->f`, including the inner read of `v->f->g`), pointer
// dereferences (`*v`), and subscripts (`v[i]`) whose base is exactly variable.
func guardedDerefEntries(branch parser.Node, variable string) []ternaryGuardEntry {
	var out []ternaryGuardEntry
	for _, fe := range branch.FindAll("field_expression") {
		base := stripGuardCasts(derefGuardBaseChild(fe))
		if base.Kind() == "identifier" && base.Text() == variable {
			out = append(out, ternaryGuardEntry{variable: variable, line: fe.StartLine()})
		}
	}
	for _, pd := range branch.FindAll("pointer_expression") {
		// pointer_expression covers both `*p` (deref) and `&x` (address-of);
		// only the deref is a null-deref sink, so skip the address-of form.
		if strings.HasPrefix(strings.TrimSpace(pd.Text()), "&") {
			continue
		}
		kids := pd.NamedChildren()
		if len(kids) == 1 {
			inner := stripGuardCasts(kids[0])
			if inner.Kind() == "identifier" && inner.Text() == variable {
				out = append(out, ternaryGuardEntry{variable: variable, line: pd.StartLine()})
			}
		}
	}
	for _, se := range branch.FindAll("subscript_expression") {
		kids := se.NamedChildren()
		if len(kids) >= 1 {
			base := stripGuardCasts(kids[0])
			if base.Kind() == "identifier" && base.Text() == variable {
				out = append(out, ternaryGuardEntry{variable: variable, line: se.StartLine()})
			}
		}
	}
	return out
}
