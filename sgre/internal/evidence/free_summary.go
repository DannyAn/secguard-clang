package evidence

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type FuncSummary struct {
	ParamDirectFrees map[int]bool
	ParamFieldFrees  map[int][]string
	// ParamMayDirectFrees records a whole-parameter free that happens on at
	// least one path, not every fall-through path (e.g. `if (ref_count <= 0)
	// free(p);` in a project release helper). It must NOT be used for
	// use-after-free / leak proofs (a may-free does not prove the object is
	// dead), but a double-free candidate needs it: a caller that frees after a
	// release helper already (conditionally) freed the object is a possible
	// double free that the AI should judge. The detector marks such events
	// may_free and the planner never auto-confirms them.
	ParamMayDirectFrees map[int]bool
	GlobalFrees         []string
	ReturnStores        []string
	// ParamWrites marks which pointer parameters the function writes through on
	// every path to exit (`*p = ...`, `p->f = ...`, `p[i] = ...`). A caller that
	// passes `&s` to such a parameter can treat s as initialized. A parameter
	// written only on some paths (e.g. a failure path skips the write) is NOT
	// marked, so TC16's interprocedural uninit stays reported.
	ParamWrites map[int]bool
	// ParamConditionalWrites marks parameters that are written through on at
	// least one path but NOT every path (a failure path skips the write). A
	// caller that guards the call's error return can still treat the output as
	// initialized on the success continuation.
	ParamConditionalWrites map[int]bool
}

type summaryMap map[string]*FuncSummary

func buildFuncSummaries(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) summaryMap {
	summaries := make(summaryMap)
	// Per-function direct write analyses are retained so forwarded writes (a
	// wrapper that passes its pointer parameter to an in-scan writer) can be
	// propagated after every direct summary exists. Without that second pass a
	// wrapper like `if (!ready) return; write_sql(sql, ...);` is graded "never
	// writes the parameter" and the caller's conditional-uninit evidence
	// (the real production shape) is lost.
	type funcWriteState struct {
		f     *db.Function
		body  parser.Node
		state *paramWriteState
	}
	var states []funcWriteState

	forEachFile(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")

		for _, f := range funcs {
			params := extractFunctionParamsFrom(funcDefs, f.StartLine)
			pointerParams := extractPointerParamsFrom(funcDefs, f.StartLine)

			state := computeParamWriteState(ctx, bodies, f, params)
			paramWrites, paramCondWrites := map[int]bool{}, map[int]bool{}
			if state != nil {
				every, some := state.states(nil, nil)
				paramWrites, paramCondWrites = every, conditionalOnly(every, some)
			}
			s := &FuncSummary{
				ParamDirectFrees:       make(map[int]bool),
				ParamFieldFrees:        make(map[int][]string),
				ParamMayDirectFrees:    make(map[int]bool),
				ParamWrites:            paramWrites,
				ParamConditionalWrites: paramCondWrites,
			}

			s.ParamDirectFrees, s.ParamFieldFrees, s.ParamMayDirectFrees = computeParamFrees(ctx, bodies, f, params, pointerParams)

			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				if !apikb.IsDeallocator(extractCallName(call)) {
					continue
				}
				args := getCallArgs(call)
				if len(args) == 0 {
					continue
				}
				globalName := extractGlobalFromArrayAccess(args[0])
				if globalName != "" && !contains(s.GlobalFrees, globalName) {
					s.GlobalFrees = append(s.GlobalFrees, globalName)
				}
			}

			s.ReturnStores = findReturnStoresFrom(returns, assigns, f)

			if len(s.ParamDirectFrees) > 0 || len(s.ParamFieldFrees) > 0 || len(s.ParamMayDirectFrees) > 0 || len(s.GlobalFrees) > 0 || len(s.ReturnStores) > 0 || len(s.ParamWrites) > 0 || len(s.ParamConditionalWrites) > 0 {
				summaries[f.Name] = s
			}
			if state != nil {
				states = append(states, funcWriteState{f: f, body: bodies[f.StartLine], state: state})
			}
		}
	})

	// Propagate writes through forwarded pointer parameters: a wrapper that
	// passes its pointer parameter to an in-scan callee that writes through it
	// also writes the caller's output on that path. The fixpoint matters for
	// the interprocedural conditional-uninit evidence: `merge_get_sql(sql)`
	// forwards `sql` to a writer only on the normal-data branch and returns
	// early otherwise, so the wrapper is a CONDITIONAL writer — the shape the
	// caller's uninit read needs. Cap the iterations: summary facts only grow,
	// so a handful settles any realistic call depth.
	nameCount := make(map[string]int, len(states))
	for _, st := range states {
		nameCount[st.f.Name]++
	}
	for iter := 0; iter < 5; iter++ {
		changed := false
		for _, st := range states {
			if nameCount[st.f.Name] != 1 {
				continue
			}
			forwardEvery, forwardSome := st.state.forwardedWriteNodes(st.body, summaries)
			every, some := st.state.states(forwardEvery, forwardSome)
			cond := conditionalOnly(every, some)
			cur := summaries[st.f.Name]
			if cur == nil {
				if len(every) == 0 && len(cond) == 0 {
					continue
				}
				summaries[st.f.Name] = &FuncSummary{ParamWrites: every, ParamConditionalWrites: cond}
				changed = true
				continue
			}
			if !boolMapsEqual(cur.ParamWrites, every) || !boolMapsEqual(cur.ParamConditionalWrites, cond) {
				cur.ParamWrites = every
				cur.ParamConditionalWrites = cond
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	// Persist the out-param write facts (function_summary.summary_json) so the
	// computed cross-function contracts survive past this detector run instead of
	// being recomputed-and-discarded every scan (P0-3 data closure). Idempotent;
	// buildFuncSummaries is called by several detectors, so a repeat write is a
	// no-op on the UNIQUE function_id key.
	if err := persistFuncSummaries(ctx, store, summaries); err != nil && logger != nil {
		logger.Warn("persist func summaries failed", "err", err)
	}

	return summaries
}

// persistFuncSummaries writes each function's out-param write state into
// function_summary.summary_json, merged with existing keys. It records which
// pointer parameters the function writes through on every path
// (outparam_writes) and on some paths (outparam_conditional_writes) — the facts
// behind the `outparam@definite` contract the uninit classifier consumes.
func persistFuncSummaries(ctx context.Context, store db.Store, summaries summaryMap) error {
	if len(summaries) == 0 {
		return nil
	}
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return fmt.Errorf("persist func summaries: list functions: %w", err)
	}
	byName := make(map[string][]*db.Function, len(funcs))
	for _, fn := range funcs {
		byName[fn.Name] = append(byName[fn.Name], fn)
	}
	for name, s := range summaries {
		if len(s.ParamWrites) == 0 && len(s.ParamConditionalWrites) == 0 {
			continue
		}
		for _, fn := range byName[name] {
			existing, err := store.GetSummaryByFunction(ctx, fn.ID)
			if err != nil {
				return fmt.Errorf("persist func summaries: get summary %d: %w", fn.ID, err)
			}
			if existing == nil {
				existing = &db.FunctionSummary{FunctionID: fn.ID}
			}
			merged, err := mergeSummaryJSON(existing.SummaryJSON, "outparam_writes", intKeys(s.ParamWrites))
			if err != nil {
				return fmt.Errorf("persist func summaries: merge writes %d: %w", fn.ID, err)
			}
			if len(s.ParamConditionalWrites) > 0 {
				merged, err = mergeSummaryJSON(merged, "outparam_conditional_writes", intKeys(s.ParamConditionalWrites))
				if err != nil {
					return fmt.Errorf("persist func summaries: merge conditional %d: %w", fn.ID, err)
				}
			}
			existing.SummaryJSON = merged
			if err := store.UpsertSummary(ctx, existing); err != nil {
				return fmt.Errorf("persist func summaries: upsert %d: %w", fn.ID, err)
			}
		}
	}
	return nil
}

// intKeys renders a map[int]bool as a sorted []int (a JSON list, not an
// object with string keys).
func intKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// paramWriteState is one function's per-parameter write-through analysis: the
// direct (`*p = ...`) and return-forwarded (`return hook(p)`) write statements,
// keyed by parameter index, plus the statement CFG used for the all-path check.
// Forwarded non-return writes are supplied separately during the summary
// fixpoint (a wrapper that hands the pointer to another in-scan writer).
type paramWriteState struct {
	cfg           *graph.StmtCFG
	params        []string
	direct        map[int]map[int]bool
	forwardReturn map[int]map[int]bool
	writeStmts    map[int][]parser.Node
	// bound is the function's parameter + local declarator name set, used as
	// the scope oracle for `(A) & x` vs `&x` disambiguation (a plain bit-and
	// argument must not be read as a forwarded parameter pointer).
	bound map[string]bool
}

// computeParamWriteState builds the direct write analysis for one function.
func computeParamWriteState(ctx context.Context, bodies map[int]parser.Node, f *db.Function, params []string) *paramWriteState {
	body := bodies[f.StartLine]
	if body.Kind() != "compound_statement" {
		return nil
	}
	cfg := buildStmtCFGFromCtx(ctx, f, body)
	st := &paramWriteState{
		cfg:           cfg,
		params:        params,
		direct:        make(map[int]map[int]bool),
		forwardReturn: make(map[int]map[int]bool),
		writeStmts:    make(map[int][]parser.Node),
		bound:         parser.FunctionBoundNamesByBody(body),
	}
	for idx, p := range params {
		if p == "" {
			continue
		}
		for _, n := range cfg.Nodes {
			if n.Kind != "stmt" {
				continue
			}
			if directWritesParam(n.Stmt, p) {
				if st.direct[idx] == nil {
					st.direct[idx] = map[int]bool{}
				}
				st.direct[idx][n.ID] = true
				st.writeStmts[idx] = append(st.writeStmts[idx], n.Stmt)
			} else if forwardsParam(n.Stmt, p) {
				// A `return hook(p)` path writes p through the hook; it counts
				// toward the every-path reachability (so a dispatch wrapper is
				// not downgraded to a conditional writer) but has no direct
				// `*p` write for the NULL-guard check.
				if st.forwardReturn[idx] == nil {
					st.forwardReturn[idx] = map[int]bool{}
				}
				st.forwardReturn[idx][n.ID] = true
			}
		}
	}
	return st
}

// states derives the every/some write facts from the direct analysis plus the
// optional forwarded non-return write nodes (param index -> CFG node IDs).
// A forwarded node is split by the callee's own reliability: a callee that
// writes on every path makes the call an every-path write for the caller; a
// callee that writes only on some paths makes it a may-write only.
func (st *paramWriteState) states(forwardEvery, forwardSome map[int]map[int]bool) (every, some map[int]bool) {
	every = make(map[int]bool)
	some = make(map[int]bool)
	for idx, p := range st.params {
		if p == "" {
			continue
		}
		someNodes := unionNodeIDs(st.direct[idx], st.forwardReturn[idx], forwardSome[idx])
		if len(someNodes) == 0 {
			continue
		}
		some[idx] = true
		everyNodes := unionNodeIDs(st.direct[idx], st.forwardReturn[idx], forwardEvery[idx])
		if len(everyNodes) > 0 &&
			(!st.cfg.ReachesAvoiding(st.cfg.Entry, everyNodes, st.cfg.Exit) || allNullGuardedWrites(st.writeStmts[idx], p)) {
			every[idx] = true
		}
	}
	return every, some
}

// forwardedWriteNodes finds calls in body that hand one of this function's
// pointer parameters to an in-scan callee, using that callee's already-computed
// summary to decide whether the call writes the parameter. `&p` and a bare `p`
// both forward the parameter (the callee writes through it or into it).
func (st *paramWriteState) forwardedWriteNodes(body parser.Node, summaries summaryMap) (every, some map[int]map[int]bool) {
	every = make(map[int]map[int]bool)
	some = make(map[int]map[int]bool)
	idxByName := make(map[string]int, len(st.params))
	for i, p := range st.params {
		if p != "" {
			idxByName[p] = i
		}
	}
	for _, call := range body.FindAll("call_expression") {
		cs := summaries[extractCallName(call)]
		if cs == nil {
			continue
		}
		node := st.cfg.NodeAt(call.StartLine())
		if node == nil || node.Kind != "stmt" {
			continue
		}
		for argIdx, arg := range getCallArgs(call) {
			name := forwardedArgParam(arg, st.bound)
			idx, ok := idxByName[name]
			if name == "" || !ok {
				continue
			}
			if cs.ParamWrites[argIdx] {
				if every[idx] == nil {
					every[idx] = map[int]bool{}
				}
				every[idx][node.ID] = true
			}
			if cs.ParamWrites[argIdx] || cs.ParamConditionalWrites[argIdx] {
				if some[idx] == nil {
					some[idx] = map[int]bool{}
				}
				some[idx][node.ID] = true
			}
		}
	}
	return every, some
}

// forwardedArgParam returns the parameter name an argument forwards, or "".
// A bare identifier forwards the pointer value; `&p` forwards the variable
// itself (a callee writing through the parameter writes p). bound is the
// scope oracle that keeps `f((flags) & x)` from reading as an address-of.
func forwardedArgParam(arg parser.Node, bound map[string]bool) string {
	if arg.Kind() == "identifier" {
		return arg.Text()
	}
	if target, ok := arg.AddressTakenTargetScoped(func(name string) bool { return bound[name] }); ok && target.Kind() == "identifier" {
		return target.Text()
	}
	return ""
}

func unionNodeIDs(sets ...map[int]bool) map[int]bool {
	out := make(map[int]bool)
	for _, s := range sets {
		for id := range s {
			out[id] = true
		}
	}
	return out
}

// conditionalOnly keeps the "some but not every" parameters: the documented
// meaning of ParamConditionalWrites (a write on at least one path, skipped on
// another). Keeping the every-path rows out of it is what lets a caller treat
// a ParamWrites hit as unconditional initialization instead of also seeing the
// same parameter as conditional.
func conditionalOnly(every, some map[int]bool) map[int]bool {
	out := make(map[int]bool)
	for idx := range some {
		if !every[idx] {
			out[idx] = true
		}
	}
	return out
}

func boolMapsEqual(a, b map[int]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// allNullGuardedWrites reports whether every write-through statement for param
// p is enclosed in an `if` whose condition establishes p is NON-NULL on the
// branch that reaches the write (`if (p) *p = ...`). A caller passing `&x`
// guarantees p is non-NULL, so the write always executes. Only NON-NULL guards
// count: `if (!p) {*p=...}` / `if (p == NULL) {*p=...}` write through p when p
// IS NULL (a dereference crash), so they are NOT safe and must not match here.
func allNullGuardedWrites(writeStmts []parser.Node, p string) bool {
	if len(writeStmts) == 0 {
		return false
	}
	for _, stmt := range writeStmts {
		if !nullGuardedWrite(stmt, p) {
			return false
		}
	}
	return true
}

func nullGuardedWrite(stmt parser.Node, p string) bool {
	for n := &stmt; n != nil; n = n.Parent() {
		if n.Kind() != "if_statement" {
			continue
		}
		cond := n.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		t := strings.TrimSpace(cond.Text())
		if t == p || t == "("+p+")" ||
			t == p+" != NULL" || t == p+" != 0" ||
			t == "NULL != "+p || t == "0 != "+p {
			return true
		}
	}
	return false
}

// computeParamFrees reports, per parameter, the whole-param and per-field frees
// that reach the function's fall-through exit, plus the may-free sets (a free on
// at least one path). The must sets feed use-after-free / leak proofs; the may
// sets feed the double-free candidate only (a conditional release helper still
// makes a later caller free a possible double free).
//
// A free on a path that RETURNS immediately (`if (err) { free(p); return -1; }`)
// is conditional: the caller resumes only on paths where the free did NOT happen,
// so propagating it into a must-set would be a false positive (cf. gz_look
// freeing state->out on a malloc-failure path). A NULL-guard
// `if (p != NULL) free(p)` falls through, so it is unconditional.
func computeParamFrees(ctx context.Context, bodies map[int]parser.Node, f *db.Function, params []string, pointerParams map[string]bool) (direct map[int]bool, field map[int][]string, mayDirect map[int]bool) {
	direct = make(map[int]bool)
	field = make(map[int][]string)
	mayDirect = make(map[int]bool)
	body := bodies[f.StartLine]
	if body.Kind() != "compound_statement" {
		return direct, field, mayDirect
	}
	cfg := buildStmtCFGFromCtx(ctx, f, body)

	// Terminator nodes dead-end a path (they do not fall through to the next
	// statement), so a free reached only via a terminator is conditional.
	terminators := make(map[int]bool)
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		switch n.Stmt.Kind() {
		case "return_statement", "break_statement", "continue_statement", "goto_statement":
			terminators[n.ID] = true
		}
	}

	directNodes := make(map[int]map[int]bool)
	fieldNodes := make(map[int]map[string]map[int]bool)
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		base, fieldName, ok := directFree(n.Stmt)
		if !ok {
			continue
		}
		for idx, p := range params {
			if p != base {
				continue
			}
			if fieldName == "" {
				// A whole-variable free only frees a pointer/array param. A
				// scalar count/flag param (`free(max_num)`) is not a real free,
				// so skip it — otherwise a caller passing the same constant to
				// two calls reads as a double-free of the count.
				if !pointerParams[p] {
					continue
				}
				if directNodes[idx] == nil {
					directNodes[idx] = map[int]bool{}
				}
				directNodes[idx][n.ID] = true
			} else {
				// A field free (`free(p->f)`) is always a pointer free no matter
				// what p's type is, so it is not gated on pointer-ness.
				if fieldNodes[idx] == nil {
					fieldNodes[idx] = map[string]map[int]bool{}
				}
				if fieldNodes[idx][fieldName] == nil {
					fieldNodes[idx][fieldName] = map[int]bool{}
				}
				fieldNodes[idx][fieldName][n.ID] = true
			}
		}
	}

	for idx := range params {
		if allFallthroughPathsFree(cfg, directNodes[idx], terminators) {
			direct[idx] = true
		} else if len(directNodes[idx]) > 0 {
			// A free exists on at least one path: may-free.
			mayDirect[idx] = true
		}
		for fieldName, nodes := range fieldNodes[idx] {
			if allFallthroughPathsFree(cfg, nodes, terminators) {
				field[idx] = append(field[idx], fieldName)
			}
		}
	}
	return direct, field, mayDirect
}

// allFallthroughPathsFree reports whether every fall-through path from entry
// to exit passes through at least one free node. This is a must-analysis: the
// free is unconditional only when the caller can assume the parameter is freed
// after the function returns normally (via fall-through, not via a terminator).
//
// `if (cond) free(p);` is conditional — the false branch doesn't free.
// `if (cond) free(p); else free(p);` is unconditional — both branches free.
// `free(p); if (cond) return;` is unconditional — the only fall-through path
// goes through the free.
func allFallthroughPathsFree(cfg *graph.StmtCFG, freeNodes map[int]bool, terminators map[int]bool) bool {
	if len(freeNodes) == 0 {
		return false
	}
	if !cfg.ReachesAvoiding(cfg.Entry, terminators, cfg.Exit) {
		return false
	}
	avoided := make(map[int]bool, len(terminators)+len(freeNodes))
	for nid := range terminators {
		avoided[nid] = true
	}
	for nid := range freeNodes {
		avoided[nid] = true
	}
	return !cfg.ReachesAvoiding(cfg.Entry, avoided, cfg.Exit)
}

// directFree reports whether stmt is a direct `free(x)` expression statement,
// returning the freed base and field ("" for a whole-variable free). It does
// not recurse into nested statements (an if/loop header must not inherit its
// body's frees).
func directFree(stmt parser.Node) (base, field string, ok bool) {
	if stmt.Kind() != "expression_statement" {
		return "", "", false
	}
	for _, child := range stmt.NamedChildren() {
		if child.Kind() != "call_expression" {
			continue
		}
		callName := extractCallName(child)
		if !apikb.IsDeallocator(callName) {
			continue
		}
		args := getCallArgs(child)
		if len(args) == 0 {
			return "", "", false
		}
		arg := args[0]
		if arg.Kind() == "identifier" {
			return arg.Text(), "", true
		}
		if arg.Kind() == "field_expression" {
			// A field free (`free(p->f)`) is only trusted for DECLARED
			// deallocators. A heuristic `_delete`/`_destroy`-named function
			// taking a field (`portrng_delete_syslog_server(host->vsys_id, ...)`)
			// deletes the ENTRY, not the field — treating host->vsys_id as freed
			// fabricates a use-after-free on the caller's later read of the
			// cleared config. Real field-frees through a project wrapper are
			// declared via secguard.toml [deallocators].
			if !apikb.IsDeclaredDeallocator(callName) {
				continue
			}
			b, f := extractFieldAccess(arg)
			return b, f, true
		}
	}
	return "", "", false
}

// directWritesParam reports whether stmt directly writes through param p
// (`*p = ...`, `p->f = ...`, `p[i] = ...`), without recursing into nested
// statements (a while/if header must not inherit its body's writes).
func directWritesParam(stmt parser.Node, p string) bool {
	for _, child := range stmt.NamedChildren() {
		if child.Kind() != "assignment_expression" && child.Kind() != "init_declarator" {
			continue
		}
		for _, name := range chainedWriteTargets(child) {
			if name == p {
				return true
			}
		}
	}
	return false
}

// forwardsParam reports whether stmt forwards pointer param p to a nested call
// and returns that call's result (`return hook(vrf, p);`). A dispatch wrapper
// (`if (hook != NULL) return hook(...p...); *p = default;`) writes p through the
// hook on the early-return path just as the fall-through writes it directly, so
// that path must count as a write for computeParamWriteStates — otherwise the
// direct write on only one path classifies the wrapper as a CONDITIONAL writer
// and a caller that doesn't guard the return is misreported as use-before-init.
// Only a bare `p` argument counts (the pointer forwarded by value); a `*p`
// argument forwards the pointed-to value, not the pointer itself, so it does not
// imply a write through p.
func forwardsParam(stmt parser.Node, p string) bool {
	if stmt.Kind() != "return_statement" {
		return false
	}
	for _, call := range stmt.FindAll("call_expression") {
		for _, arg := range getCallArgs(call) {
			if arg.Kind() == "identifier" && arg.Text() == p {
				return true
			}
		}
	}
	return false
}

// chainedWriteTargets returns the variable name of every write target in a
// (possibly chained) assignment. `*a = *b = *c = 0` writes through a, b and c,
// but the previous code only looked at the outermost LHS (a), so `*b`/`*c`
// (e.g. win32_translate_open_mode's chained `*pdwShareMode = ...`) were not
// recorded as output-param writes.
func chainedWriteTargets(assign parser.Node) []string {
	var names []string
	cur := assign
	for cur.Kind() == "assignment_expression" {
		c := cur.NamedChildren()
		if len(c) < 2 {
			break
		}
		names = append(names, extractVarName(c[0]))
		cur = c[1]
	}
	return names
}

// functionBodyMap builds a start-line → compound_statement body map from a
// file's function_definition nodes, so per-function body lookup is O(1) instead
// of re-scanning all definitions per function (the old extractFunctionBodyFrom
// was O(F²) per file).
func functionBodyMap(funcDefs []parser.Node) map[int]parser.Node {
	m := make(map[int]parser.Node, len(funcDefs))
	for _, fn := range funcDefs {
		if body := fn.FindFirst("compound_statement"); body != nil {
			m[fn.StartLine()] = *body
		}
	}
	return m
}

// functionDefinitionMap indexes a file's function_definition nodes by start
// line, for callers that need the definition itself (parameter list, scope
// oracle) and not just the body.
func functionDefinitionMap(funcDefs []parser.Node) map[int]parser.Node {
	m := make(map[int]parser.Node, len(funcDefs))
	for _, fn := range funcDefs {
		m[fn.StartLine()] = fn
	}
	return m
}

func findReturnStoresFrom(returns, assigns []parser.Node, f *db.Function) []string {
	var stores []string
	seen := make(map[string]bool)

	hasReturn := false
	for _, ret := range returns {
		if funcLineRange(f, ret.StartLine()) {
			hasReturn = true
			break
		}
	}
	if !hasReturn {
		return nil
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		globalName := extractGlobalFromArrayAccess(lhs)
		if globalName != "" && !seen[globalName] {
			seen[globalName] = true
			stores = append(stores, globalName)
		}
	}

	return stores
}

func extractFieldAccess(node parser.Node) (string, string) {
	children := node.NamedChildren()
	if len(children) < 2 {
		return "", ""
	}
	baseVar := ""
	if children[0].Kind() == "identifier" {
		baseVar = children[0].Text()
	} else {
		// Macro call-site recovery: the base identifier is buried in an ERROR
		// child (`LIST_FOR_EACH(x, h)\n q->value` parses as
		// field_expression[call_expression, ERROR(q), field_identifier]).
		for _, child := range children {
			if child.Kind() == "ERROR" {
				if name := firstIdentifier(child); name != "" {
					baseVar = name
					break
				}
			}
		}
	}
	fieldName := ""
	for _, child := range children {
		if child.Kind() == "field_identifier" {
			fieldName = child.Text()
		}
	}
	return baseVar, fieldName
}

// subscriptAccess returns (base, field) for a subscript `a[0]` / `a[i]`. A
// constant index keeps `a[0]` distinct from `a[1]`; a variable index is merged to
// `a[]` (the same array slot), which is conservative: free(a[i]) then use(a[j])
// with i != j may be a false positive that the AI agent refines (full object
// identity / points-to is the follow-up that would separate them).
func subscriptAccess(node parser.Node) (string, string) {
	if node.Kind() != "subscript_expression" {
		return "", ""
	}
	children := node.NamedChildren()
	if len(children) < 2 {
		return "", ""
	}
	base := ""
	if children[0].Kind() == "identifier" {
		base = children[0].Text()
	} else if children[0].Kind() == "call_expression" {
		// Macro call-site recovery: `LIST_FOR_EACH(x, h)\n q[0]` parses as
		// subscript_expression[call_expression, ERROR(q), number_literal].
		for _, child := range children {
			if child.Kind() == "ERROR" {
				base = firstIdentifier(child)
				break
			}
		}
	}
	if base == "" {
		return "", ""
	}
	index := children[len(children)-1].Text()
	if isConstantIndex(index) {
		return base, base + "[" + index + "]"
	}
	return base, base + "[]"
}

// subscriptBaseIndex returns (base, index) for a subscript expression, recovering
// the base identifier from an ERROR child when a macro call site glues a
// call_expression as children[0] (`LIST_FOR_EACH(x, h)\n arr[10]` parses as
// subscript_expression[call_expression, ERROR(arr), number_literal]).
func subscriptBaseIndex(sub parser.Node) (string, string, bool) {
	children := sub.NamedChildren()
	if len(children) < 2 {
		return "", "", false
	}
	base := ""
	if children[0].Kind() == "identifier" {
		base = children[0].Text()
	} else if children[0].Kind() == "call_expression" {
		for _, child := range children {
			if child.Kind() == "ERROR" {
				base = firstIdentifier(child)
				break
			}
		}
	}
	if base == "" {
		return "", "", false
	}
	return base, children[len(children)-1].Text(), true
}

func extractGlobalFromArrayAccess(node parser.Node) string {
	if node.Kind() == "subscript_expression" {
		children := node.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			name := children[0].Text()
			if strings.HasPrefix(name, "g_") {
				return name
			}
		}
	}
	if node.Kind() == "field_expression" {
		children := node.NamedChildren()
		if len(children) >= 1 {
			return extractGlobalFromArrayAccess(children[0])
		}
	}
	return ""
}

func getCallArgs(call parser.Node) []parser.Node {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			return child.NamedChildren()
		}
	}
	return nil
}

func extractFunctionParamsFrom(funcDefs []parser.Node, startLine int) []string {
	for _, fnNode := range funcDefs {
		if fnNode.StartLine() != startLine {
			continue
		}
		for _, child := range fnNode.NamedChildren() {
			if child.Kind() == "function_declarator" {
				return extractParamsFromDeclarator(child)
			}
			if child.Kind() == "pointer_declarator" {
				for _, gc := range child.NamedChildren() {
					if gc.Kind() == "function_declarator" {
						return extractParamsFromDeclarator(gc)
					}
				}
			}
		}
	}
	return nil
}

func extractPointerParamsFrom(funcDefs []parser.Node, startLine int) map[string]bool {
	pointerParams := make(map[string]bool)
	for _, fnNode := range funcDefs {
		if fnNode.StartLine() != startLine {
			continue
		}
		for _, child := range fnNode.NamedChildren() {
			if child.Kind() == "function_declarator" {
				collectPointerParams(child, pointerParams)
			}
			if child.Kind() == "pointer_declarator" {
				for _, gc := range child.NamedChildren() {
					if gc.Kind() == "function_declarator" {
						collectPointerParams(gc, pointerParams)
					}
				}
			}
		}
	}
	return pointerParams
}

func collectPointerParams(decl parser.Node, pointerParams map[string]bool) {
	for _, child := range decl.NamedChildren() {
		if child.Kind() != "parameter_list" {
			continue
		}
		for _, param := range child.NamedChildren() {
			if param.Kind() != "parameter_declaration" {
				continue
			}
			if isPointerParam(param) {
				if v := extractVarFromDeclarator(param); v != "" {
					pointerParams[v] = true
				}
			}
		}
	}
}

func isPointerParam(param parser.Node) bool {
	ptr := false
	scalar := false
	aggregate := false
	for _, child := range param.NamedChildren() {
		switch child.Kind() {
		case "pointer_declarator", "abstract_pointer_declarator",
			"array_declarator", "abstract_array_declarator":
			ptr = true
		case "primitive_type", "sized_type_specifier":
			scalar = true
		case "struct_specifier", "union_specifier", "enum_specifier":
			aggregate = true
		}
	}
	if ptr {
		return true
	}
	if scalar || aggregate {
		return false
	}
	// A typedef name (type_identifier) whose target is not visible here. It may
	// hide a pointer (`typedef struct X *X_t`) or a scalar (`typedef unsigned
	// int u32`). Treat it as a pointer so genuine double-frees through
	// typedef'd pointer params are never missed; only unambiguous scalars are
	// excluded.
	return true
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

type aliasInfo struct {
	baseVar string
	field   string
	line    int // the source line where this alias was established
}

func findAliases(f *db.Function, inits, assigns []parser.Node) map[string]aliasInfo {
	aliases := make(map[string]aliasInfo)

	// Declaration initializers: `int *q = p;` / `int *q = p->f;`.
	for _, decl := range inits {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		lhs, rhs, ok := decl.AssignParts()
		if !ok {
			continue
		}

		aliasVar := extractVarFromDeclarator(lhs)
		if aliasVar == "" {
			continue
		}
		recordAlias(aliases, aliasVar, rhs, decl.StartLine())
	}

	// Plain assignments: `q = p;` / `q = p->f;`. The previous version only
	// scanned init_declarator, so `p = malloc(); q = p; free(p); *q` was missed
	// (q is an alias of p established by a statement, not a declaration).
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		if lhs.Kind() != "identifier" {
			continue
		}
		recordAlias(aliases, lhs.Text(), children[1], assign.StartLine())
	}

	return aliases
}

// recordAlias records that aliasVar aliases the object denoted by rhs (a bare
// identifier, a field access base.field, or a cast/parenthesized spelling of
// either: `q = (T *)p`, `q = (p->f)`).
func recordAlias(aliases map[string]aliasInfo, aliasVar string, rhs parser.Node, line int) {
	for rhs.Kind() == "cast_expression" || rhs.Kind() == "parenthesized_expression" {
		children := rhs.NamedChildren()
		if len(children) == 0 {
			return
		}
		rhs = children[0]
	}
	if rhs.Kind() == "identifier" {
		aliases[aliasVar] = aliasInfo{baseVar: rhs.Text(), field: "", line: line}
		return
	}
	if rhs.Kind() == "field_expression" {
		baseVar, fieldName := extractFieldAccess(rhs)
		if baseVar != "" {
			aliases[aliasVar] = aliasInfo{baseVar: baseVar, field: fieldName, line: line}
		}
	}
}

func extractVarFromDeclarator(node parser.Node) string {
	if node.Kind() == "identifier" {
		return node.Text()
	}
	for _, child := range node.NamedChildren() {
		if v := extractVarFromDeclarator(child); v != "" {
			return v
		}
	}
	return ""
}

func (m summaryMap) hasSummary(name string) bool {
	_, ok := m[name]
	return ok
}
