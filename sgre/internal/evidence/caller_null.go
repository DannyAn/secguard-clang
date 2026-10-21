package evidence

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// CallerNullDetector closes the inter-procedural null gap for function
// parameters: a callee that dereferences its parameter without a guard has an
// implicit non-null precondition, and that precondition is violated when a
// caller can pass NULL for that parameter. It emits a NULL_VALUE with origin
// "caller_null" for each such (callee, parameter) pair, which the null-deref
// flow then seeds at the callee's entry — so `process(NULL)` reaches
// `ctx->field` in process.
//
// Whether a parameter CAN be NULL is decided by an OPEN-CHAIN fixpoint over
// the in-tree call graph, NOT by "the immediate caller did not prove the
// argument non-null" (that reading floods: the C convention is to guard once
// at the outer entry while inner functions assume non-null by contract, so
// almost every forwarded argument is locally unproven). A parameter is open
// when a possibly-null value can actually REACH it:
//
//   - some in-tree call site passes a literal NULL (definite witness);
//   - the function has ZERO in-tree call sites and is externally callable
//     (non-static, or static with its address taken; main is exempt) — every
//     pointer parameter is open to the outside world;
//   - an unguarded call site forwards the CALLER'S OWN parameter, which is
//     itself open — openness propagates down forwarding chains.
//
// A guarded call site (early-return / positive branch / short-circuit /
// assert — classifyArg "safe") closes its edge, so a parameter guarded on ANY
// link of its chain never surfaces. Local-variable and opaque-expression
// arguments seed nothing (an analyzer limitation is not NULL evidence).
// Same-name static overloads across files are skipped (never guessed).
type CallerNullDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewCallerNullDetector(store db.Store, p *parser.Parser, logger *log.Logger) *CallerNullDetector {
	return &CallerNullDetector{store: store, parser: p, logger: logger}
}

func (d *CallerNullDetector) Name() string { return "caller_null" }

func (d *CallerNullDetector) Domain() string { return "memory" }

func (d *CallerNullDetector) Capabilities() []string {
	return []string{"caller-null", "interprocedural-param-null"}
}

type calleeParamInfo struct {
	fn    *db.Function
	names []string
	types []string
}

func (d *CallerNullDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	callees := d.buildCalleeIndex(ctx)
	infoByFnID := make(map[int64]calleeParamInfo, len(callees))
	for _, info := range callees {
		infoByFnID[info.fn.ID] = info
	}

	// sites aggregates every in-tree call edge that reaches a (callee,
	// pointer-parameter) pair. hasCaller records that the pair HAS a call site
	// (a guarded site proves non-null on that edge and closes the chain);
	// definite records a literal-NULL witness; fwds records the parameter
	// FORWARDING edges (the argument is the caller's own unguarded parameter
	// j) that the open-chain fixpoint propagates along.
	type siteAgg struct {
		definite  bool
		caller    string
		line      int
		argText   string
		hasCaller bool
	}
	sites := map[int64]map[int]*siteAgg{}
	type fwdEdge struct {
		callerID    int64
		callerParam int
		calleeID    int64
		calleeParam int
		callerName  string
		argText     string
	}
	var fwds []fwdEdge
	calledNames := map[string]bool{}
	addrTaken := map[string]bool{}
	consumedParams := map[int64]map[string]bool{}
	// The tree-wide defined-type census (layout-visible names only — a
	// forward-declaration typedef stays opaque) gates the open-entry base.
	// It is built over EVERY indexed file: a header that defines a struct but
	// no function is exactly where a normal C project keeps its type layouts,
	// and forEachFile would skip it, marking every header-defined type opaque
	// and opening far more entries than the v0.9.4 contract allows.
	definedTypes := map[string]bool{}
	if err := forEachIndexedFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node) {
		collectDefinedTypes(root, definedTypes)
	}); err != nil {
		return result, fmt.Errorf("caller null: type census: %w", err)
	}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		ifs := root.FindAll("if_statement")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")
		fnDefs := root.FindAll("function_definition")

		// A call argument that names an array (global or caller-local) can never
		// be NULL, so it must not seed a caller_null source. Precompute per caller
		// to avoid re-walking the tree for every call site.
		nonNullArrays := make(map[int64]map[string]bool, len(funcs))
		callerParams := make(map[int64]map[string]int, len(funcs))

		for _, fn := range funcs {
			nonNullArrays[fn.ID] = collectNonNullableArrays(root, fn)
			fnDef := findFnDefByName(fnDefs, fn.Name)
			if fnDef.Kind() == "" {
				continue
			}
			_, names, _ := functionParamNames(fnDef)
			idx := make(map[string]int, len(names))
			for i, n := range names {
				idx[n] = i
			}
			callerParams[fn.ID] = idx
			consumedParams[fn.ID] = paramConsumedIn(fnDef)
		}

		for _, unary := range root.FindAll("unary_expression") {
			if !strings.HasPrefix(strings.TrimSpace(unary.Text()), "&") {
				continue
			}
			for _, c := range unary.NamedChildren() {
				if c.Kind() == "identifier" {
					addrTaken[c.Text()] = true
				}
			}
		}

		for _, call := range calls {
			callee := calleeName(call)
			if callee == "" {
				continue
			}
			// calledNames records every callee NAME seen in a call, index or no
			// index: an overloaded (duplicate-definition) name must never be
			// mistaken for a zero-call-site open entry.
			calledNames[callee] = true
			info, ok := callees[callee]
			if !ok {
				continue
			}
			var caller *db.Function
			for _, fn := range funcs {
				if funcLineRange(fn, call.StartLine()) {
					caller = fn
					break
				}
			}
			if caller == nil {
				continue
			}
			args := getCallArgs(call)
			for i, arg := range args {
				if i >= len(info.names) || info.names[i] == "..." {
					continue
				}
				if !strings.HasSuffix(strings.TrimSpace(info.types[i]), "*") {
					continue
				}
				if sites[info.fn.ID] == nil {
					sites[info.fn.ID] = map[int]*siteAgg{}
				}
				agg := sites[info.fn.ID][i]
				if agg == nil {
					agg = &siteAgg{}
					sites[info.fn.ID][i] = agg
				}
				agg.hasCaller = true
				kind, definite, fwdIdx := d.classifyArg(arg, caller, callerParams[caller.ID], ifs, assigns, calls, nonNullArrays[caller.ID], call)
				if definite && !agg.definite {
					agg.definite = true
					agg.caller = caller.Name
					agg.line = call.StartLine()
					agg.argText = arg.Text()
				}
				if kind == "fwd" {
					fwds = append(fwds, fwdEdge{callerID: caller.ID, callerParam: fwdIdx, calleeID: info.fn.ID, calleeParam: i, callerName: caller.Name, argText: arg.Text()})
				}
			}
		}
	})
	if err != nil {
		return result, err
	}

	// Open-chain fixpoint. A parameter's value is OPEN when a possibly-null
	// value can actually reach it from an unguarded entry:
	//
	//   - base (witness): some in-tree call site passes a literal NULL;
	//   - base (open entry): the function has ZERO in-tree call sites and is
	//     externally callable (non-static, or static with its address taken;
	//     main is exempt) — every pointer parameter is open;
	//   - propagation: a call site whose argument is the caller's own
	//     UNGUARDED parameter j forwards that parameter's openness.
	//
	// A guarded call site (early return / positive branch / short-circuit /
	// assert — classifyArg "safe") closes its edge, so a parameter whose every
	// call chain is guarded somewhere stays closed and never surfaces. This is
	// the candidate-volume contract: the C convention "guard once at the outer
	// entry, inner functions assume non-null by contract" must NOT explode
	// into one candidate per forwarded parameter — the guard on ANY link of
	// the chain closes the whole chain. An "unproven" argument that is NOT a
	// forwarded parameter (a local variable, an opaque expression) seeds
	// nothing: that is the analyzer's limitation, not evidence of NULL.
	open := map[int64]map[int]bool{}
	definite := map[int64]map[int]bool{}
	for calleeID, params := range sites {
		for i, agg := range params {
			if !agg.definite {
				continue
			}
			if open[calleeID] == nil {
				open[calleeID] = map[int]bool{}
			}
			open[calleeID][i] = true
			if definite[calleeID] == nil {
				definite[calleeID] = map[int]bool{}
			}
			definite[calleeID][i] = true
		}
	}
	hasEntryPoint := scanHasEntryPoint(ctx, d.store)
	for name, info := range callees {
		if calledNames[name] || info.fn.Name == "main" {
			continue
		}
		if info.fn.IsStatic && !addrTaken[name] {
			continue
		}
		for i, t := range info.types {
			if t == "..." || !strings.HasSuffix(strings.TrimSpace(t), "*") {
				continue
			}
			// IN-TREE-INVARIANT POLICY (formerly named the "v0.9.4
			// layout-visible type contract"). Layout visibility answers "do we
			// know the struct's fields", NOT "can this VALUE be NULL" — the two
			// are orthogonal: an exported API taking the project's OWN struct
			// is exactly where an out-of-tree caller passes NULL, while an
			// external typedef whose every in-tree caller is guarded is safe.
			// The gate below is therefore a PRECISION policy, not a proof, and
			// it is only assumed for a COMPLETE-PROGRAM scan (an entry point
			// exists): there the project's own conventions are in-tree and a
			// boundary symbol with a visible layout is most likely an internal
			// function or an in-tree-registered callback. A BOUNDARY scan (no
			// `main`: a library, a partial tree) has no such convention —
			// its edge IS an external ABI, so every boundary parameter is
			// fail-open regardless of where its type is defined.
			if hasEntryPoint && !typeSpellingOpaque(t, definedTypes) {
				continue
			}
			if open[info.fn.ID] == nil {
				open[info.fn.ID] = map[int]bool{}
			}
			open[info.fn.ID][i] = true
		}
	}
	fwdBy := map[int64]map[int]fwdEdge{}
	for changed := true; changed; {
		changed = false
		for _, e := range fwds {
			if open[e.callerID] == nil || !open[e.callerID][e.callerParam] {
				continue
			}
			if open[e.calleeID] == nil {
				open[e.calleeID] = map[int]bool{}
			}
			if !open[e.calleeID][e.calleeParam] {
				open[e.calleeID][e.calleeParam] = true
				changed = true
				if fwdBy[e.calleeID] == nil {
					fwdBy[e.calleeID] = map[int]fwdEdge{}
				}
				fwdBy[e.calleeID][e.calleeParam] = e
			}
		}
	}

	// No deref filter on the seed: a parameter consumed INDIRECTLY (cast into
	// a local, then dereferenced — `T *t = (T *)msg; t->f`) has no direct deref
	// base, and a source with no sink at all simply never becomes a candidate
	// (the planner only reports variables a DEREFERENCE event names).
	for fnID, params := range open {
		info, ok := infoByFnID[fnID]
		if !ok {
			continue
		}
		consumed := consumedParams[fnID]
		for i := range params {
			if i >= len(info.names) || info.names[i] == "..." {
				continue
			}
			// A PURE FORWARDER (the parameter is only ever passed on as a call
			// argument, never dereferenced nor stored locally in this body)
			// does not seed: the chain continues in the callee, which has its
			// own candidate at the actual dereference — seeding here too would
			// report the same open chain once per forwarding level.
			if consumed != nil && !consumed[info.names[i]] {
				continue
			}
			props := map[string]string{
				"variable": info.names[i],
				"origin":   "caller_null",
			}
			if definite[fnID] != nil && definite[fnID][i] {
				agg := sites[fnID][i]
				props["definite"] = "true"
				if agg != nil {
					props["function"] = agg.caller
					props["expression"] = agg.argText
				}
			} else {
				// An open chain without a literal-NULL witness: the value CAN be
				// NULL (it flows from an unguarded entry), but nothing proves it
				// IS — suspected, never auto-confirmed. "chain": "open" is what
				// keeps the planner's onlyUnprovenCallerNullSources dismissal
				// away from this event. The first forwarding caller names the
				// link the openness came through (an open-entry function has
				// no forwarding caller and no function field).
				props["definite"] = "false"
				props["chain"] = "open"
				if e := fwdBy[fnID][i]; e.callerName != "" {
					props["function"] = e.callerName
					props["expression"] = e.argText
				}
			}
			if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", fnID, &db.Location{FileID: info.fn.FileID, Line: info.fn.StartLine}, props) {
				result.EventsCreated++
			}
		}
	}
	return result, nil
}

// buildCalleeIndex maps each uniquely-defined function name to its parameter
// names/types and its function row. Same-name static overloads across files are
// dropped (ambiguous, never guessed).
func (d *CallerNullDetector) buildCalleeIndex(ctx context.Context) map[string]calleeParamInfo {
	out := map[string]calleeParamInfo{}
	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return out
	}
	byName := map[string]*db.Function{}
	dup := map[string]bool{}
	for _, fn := range funcs {
		if _, seen := byName[fn.Name]; seen {
			dup[fn.Name] = true
			continue
		}
		byName[fn.Name] = fn
	}
	files, err := d.store.ListFiles(ctx)
	if err != nil {
		return out
	}
	for _, file := range files {
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		for _, fnDef := range tree.RootNode().FindAll("function_definition") {
			name, names, types := functionParamNames(fnDef)
			if name == "" || dup[name] {
				continue
			}
			fn := byName[name]
			if fn == nil {
				continue
			}
			out[name] = calleeParamInfo{fn: fn, names: names, types: types}
		}
	}
	return out
}

func functionParamNames(fnDef parser.Node) (string, []string, []string) {
	var name string
	var names, types []string
	for _, child := range fnDef.NamedChildren() {
		if child.Kind() != "function_declarator" {
			continue
		}
		for _, c := range child.NamedChildren() {
			switch c.Kind() {
			case "identifier":
				name = c.Text()
			case "parameter_list":
				for _, param := range c.NamedChildren() {
					switch param.Kind() {
					case "parameter_declaration":
						names = append(names, paramName(param))
						types = append(types, normalizeSpelling(typeSpelling(param)))
					case "variadic_parameter", "variadic_type_identifier":
						names = append(names, "...")
						types = append(types, "...")
					}
				}
			}
		}
	}
	return name, names, types
}

// classifyArg classifies a call argument's nullability at the call site. The
// third return value is the caller's parameter index the argument forwards
// (-1 when it is not a forward), which is what the open-chain fixpoint
// propagates along.
//
//   - "null" + definite=true: a literal NULL witness;
//   - "safe": provably non-null on this edge (&x / string literal / guarded
//     variable / non-null array) — the edge is CLOSED, openness does not
//     propagate through it;
//   - "fwd": the argument is the caller's own UNGUARDED parameter — the edge
//     carries the caller parameter's openness downstream;
//   - "other": a local variable or opaque expression — an analyzer
//     limitation, neither seeded nor propagated.
func (d *CallerNullDetector) classifyArg(arg parser.Node, caller *db.Function, callerParams map[string]int, ifs, assigns, calls []parser.Node, nonNullArrays map[string]bool, call parser.Node) (string, bool, int) {
	classifyIdent := func(name string) (string, bool, int) {
		if name == "NULL" {
			return "null", true, -1
		}
		if nonNullArrays[name] {
			return "safe", false, -1
		}
		if callerGuardsVar(caller, ifs, assigns, calls, name, call) {
			return "safe", false, -1
		}
		if idx, ok := callerParams[name]; ok {
			return "fwd", false, idx
		}
		return "other", false, -1
	}
	switch arg.Kind() {
	case "null":
		// tree-sitter-c parses `NULL` as a `null` literal node (not an
		// identifier), so a literal NULL argument is a DEFINITE null source.
		return "null", true, -1
	case "identifier":
		return classifyIdent(arg.Text())
	case "number_literal":
		if strings.TrimSpace(arg.Text()) == "0" {
			return "null", true, -1
		}
		return "safe", false, -1
	case "cast_expression":
		op := castOperand(arg)
		if op.Kind() == "null" || (op.Kind() == "identifier" && op.Text() == "NULL") {
			return "null", true, -1
		}
		if op.Kind() == "number_literal" && strings.TrimSpace(op.Text()) == "0" {
			return "null", true, -1
		}
		if op.Kind() == "identifier" {
			return classifyIdent(op.Text())
		}
		if isNonNullExpr(arg) {
			return "safe", false, -1
		}
		return "other", false, -1
	}
	if isNonNullExpr(arg) {
		return "safe", false, -1
	}
	return "other", false, -1
}

// callerGuardsVar reports whether the caller proves varName non-null at the
// call. Four idioms count: a dominating early-return null check
// (`if (v == NULL) return;`), a positive branch (`if (v != NULL) { f(v); }`),
// a short-circuit conjunction (`v != NULL && f(v)`), and an assert
// precondition (`assert(v != NULL); f(v);`).
func callerGuardsVar(f *db.Function, ifs, assigns, calls []parser.Node, varName string, call parser.Node) bool {
	if callerEarlyReturnGuards(f, ifs, assigns, varName, call) {
		return true
	}
	if callerPositiveBranchGuards(f, ifs, assigns, varName, call) {
		return true
	}
	if callerShortCircuitGuards(varName, call) {
		return true
	}
	return callerAssertGuards(f, assigns, calls, varName, call)
}

// callerEarlyReturnGuards covers a dominating early-return null check
// (`if (v == NULL) return;`). The guard must lexically precede the call (byte
// offset, so a same-line `if (v == NULL) return; f(v);` still counts) and its
// non-null scope must cover the call line.
func callerEarlyReturnGuards(f *db.Function, ifs, assigns []parser.Node, varName string, call parser.Node) bool {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		if ifNode.EndByte() > call.StartByte() {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		consequence := ifNode.ChildByFieldName("consequence")
		if consequence == nil || !isExitBlock(*consequence) {
			continue
		}
		guarded := false
		for _, gv := range earlyReturnGuardedVars(*condition) {
			if gv == varName {
				guarded = true
				break
			}
		}
		if !guarded {
			continue
		}
		scopeEnd := guardExitBound(*consequence, ifNode, f)
		if end := guardScopeEnd(assigns, f, varName, ifNode.EndLine()); end < scopeEnd {
			scopeEnd = end
		}
		if call.StartLine() <= scopeEnd {
			return true
		}
	}
	return false
}

// callerPositiveBranchGuards covers `if (v != NULL) { ...; f(v); ... }`: a
// call inside the consequence runs only when the condition is TRUE — exactly
// the direction that establishes v non-null. The else branch proves nothing
// (a call there sees v NULL), and a reassignment of v inside the branch
// truncates the fact.
func callerPositiveBranchGuards(f *db.Function, ifs, assigns []parser.Node, varName string, call parser.Node) bool {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		consequence := ifNode.ChildByFieldName("consequence")
		if condition == nil || consequence == nil {
			continue
		}
		if call.StartByte() < consequence.StartByte() || call.EndByte() > consequence.EndByte() {
			continue
		}
		guarded := false
		for _, gv := range parser.GuardedNonnullVars(*condition) {
			if gv == varName {
				guarded = true
				break
			}
		}
		if !guarded {
			continue
		}
		if call.StartLine() <= guardScopeEnd(assigns, f, varName, consequence.StartLine()-1) {
			return true
		}
	}
	return false
}

// callerShortCircuitGuards covers `v != NULL && f(v)` and nested conjunctions:
// the right operand of && evaluates only when the left is TRUE, so a call
// inside the right operand of an ancestor && whose left establishes varName
// non-null is guarded. An || ancestor proves nothing about its right side
// (that side runs when the left is FALSE) and is skipped; the call must be
// byte-contained in the right operand so `a && b || f(v)` (where f runs with
// a possibly-false left) does not match the && layer.
func callerShortCircuitGuards(varName string, call parser.Node) bool {
	for node := call.Parent(); node != nil; node = node.Parent() {
		if node.Kind() != "binary_expression" || parser.BinaryOperator(*node) != "&&" {
			continue
		}
		kids := node.NamedChildren()
		if len(kids) < 2 {
			continue
		}
		if call.StartByte() < kids[1].StartByte() || call.EndByte() > kids[1].EndByte() {
			continue
		}
		for _, gv := range parser.GuardedNonnullVars(kids[0]) {
			if gv == varName {
				return true
			}
		}
	}
	return false
}

// callerAssertGuards covers `assert(v != NULL); f(v);`: the assert aborts on
// the false branch, so the variables it establishes non-null hold on the
// fall-through up to a reassignment.
func callerAssertGuards(f *db.Function, assigns, calls []parser.Node, varName string, call parser.Node) bool {
	for _, ac := range calls {
		if !funcLineRange(f, ac.StartLine()) {
			continue
		}
		if ac.EndByte() > call.StartByte() {
			continue
		}
		if calleeName(ac) != "assert" {
			continue
		}
		if p := ac.Parent(); p == nil || p.Kind() != "expression_statement" {
			continue
		}
		args := getCallArgs(ac)
		if len(args) == 0 {
			continue
		}
		for _, gv := range assertGuardedVars(args[0]) {
			if gv == varName && call.StartLine() <= guardScopeEnd(assigns, f, varName, ac.StartLine()) {
				return true
			}
		}
	}
	return false
}

// paramConsumedIn returns the set of parameter names a function body actually
// CONSUMES: a direct dereference base (`p->f`, `p[i]`, `*p`) or a local
// re-storage (`T *t = (T *)p;` — the RHS names the parameter, cast/paren
// stripped). Merely forwarding the parameter as a call argument does not
// count: the callee's own candidate covers the chain's continuation.
func paramConsumedIn(fnDef parser.Node) map[string]bool {
	consumed := derefBaseTexts(fnDef)
	record := func(n parser.Node) {
		_, rhs, ok := n.AssignParts()
		if !ok {
			return
		}
		inner := stripCasts(rhs)
		if inner.Kind() == "identifier" {
			consumed[strings.TrimSpace(inner.Text())] = true
		}
	}
	for _, a := range fnDef.FindAll("assignment_expression") {
		record(a)
	}
	for _, i := range fnDef.FindAll("init_declarator") {
		record(i)
	}
	return consumed
}
