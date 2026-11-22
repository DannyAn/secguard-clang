package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// callResultChecked reports whether the call's value is consumed directly by a
// comparison, a `!` negation, or a branch/loop condition — i.e. validated at
// the call site without going through a named variable.
func callResultChecked(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "binary_expression":
			if hasCompareOp(*p) {
				return true
			}
		case "unary_expression":
			if strings.HasPrefix(strings.TrimSpace(p.Text()), "!") {
				return true
			}
		case "if_statement", "while_statement", "for_statement", "do_statement", "switch_statement":
			return true
		case "return_statement", "expression_statement", "compound_statement",
			"declaration", "argument_list", "assignment_expression", "init_declarator":
			return false
		}
	}
	return false
}

// insideVoidCast reports whether an identifier is the operand of a cast to
// void (`(void)p`) — the programmer's explicit "discard this value"
// annotation. It walks parenthesized expressions but stops at the statement
// boundary, so a `(void)` on an unrelated expression cannot swallow a later use.
func insideVoidCast(id parser.Node) bool {
	for p := id.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "cast_expression":
			for _, c := range p.NamedChildren() {
				if c.Kind() == "type_descriptor" {
					return typeSpelling(c) == "void"
				}
			}
			return false
		case "parenthesized_expression":
			continue
		case "expression_statement", "function_definition":
			return false
		}
	}
	return false
}

// resultVoidDiscarded reports whether an assigned result is consumed ONLY by
// explicit `(void)` casts after the call (with free/sizeof/rebind occurrences
// also tolerated). It is distinct from neverUsedAfter's dead store (no
// occurrence at all): the value IS discarded deliberately, so the failure
// cannot be observed, but the event stays as a lead carrying a `discard@` fact
// so the AI dismisses from the hint instead of reading the source to find the
// `(void)p` (round3 idm_new_idmgr).
func resultVoidDiscarded(vars []string, call parser.Node, f *db.Function, ids []parser.Node) bool {
	targets := make(map[string]bool, len(vars))
	for _, v := range vars {
		if v == "" || strings.ContainsAny(v, ".[>*") {
			return false
		}
		targets[v] = true
	}
	discarded := false
	for _, id := range ids {
		if !targets[id.Text()] || !funcLineRange(f, id.StartLine()) || id.StartLine() <= call.StartLine() {
			continue
		}
		if insideSizeof(id) || isRebindTarget(id) || nullSafeFreedArg(id) {
			continue
		}
		if insideVoidCast(id) {
			discarded = true
			continue
		}
		return false // a real observable use — not a pure discard
	}
	return discarded
}

// isVoidCast reports whether the call is wrapped in a (void) cast — the
// programmer's explicit "intentionally ignoring this return value" annotation.
// `(void)foo()` → true; `(int)foo()` / `foo()` → false.
func isVoidCast(call parser.Node) bool {
	p := call.Parent()
	if p.Kind() != "cast_expression" {
		return false
	}
	for _, child := range p.NamedChildren() {
		if child.Kind() == "type_descriptor" {
			return typeSpelling(child) == "void"
		}
	}
	return false
}

// callResultReturned reports whether the call's result flows straight into a
// `return` (possibly through casts/parentheses) without being stored in a
// variable or otherwise consumed first. `void *x_malloc(size_t n) { return
// malloc(n); }` is a passthrough allocator: the caller — which sees x_malloc's
// return value — is responsible for the NULL check, so the wrapper itself must
// not be flagged as an unchecked return.
func callResultReturned(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "parenthesized_expression", "cast_expression":
			continue
		case "return_statement":
			return true
		default:
			return false
		}
	}
	return false
}

// assignedVarsOfCall returns the storage locations the call's result is assigned
// into, collecting ALL targets in a (possibly chained) assignment. For
// `v = call(...)` / `T v = call(...)` it returns [v]; for a chained assignment
// `a = b = call(...)` it returns [b, a] (innermost first), so a null-check on
// EITHER target suppresses the unchecked-return event. Returns nil when the
// result is not stored in a named variable.
func assignedVarsOfCall(call parser.Node) []string {
	var vars []string
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression":
			named := p.NamedChildren()
			if len(named) < 2 {
				return vars
			}
			vars = append(vars, assignedLocationText(named[0]))
		case "init_declarator":
			named := p.NamedChildren()
			if len(named) < 2 {
				return vars
			}
			vars = append(vars, assignedLocationText(named[0]))
			return vars
		case "parenthesized_expression", "cast_expression", "binary_expression",
			"argument_list", "call_expression", "field_expression", "subscript_expression":
			continue
		default:
			return vars
		}
	}
	return vars
}

// assignedLocationText returns the storage location an assignment writes: a
// bare variable/field/subscript, or the POINTED-TO location `*p` for
// `*p = malloc(n)`. Unlike assignedVariable (which treats `*p = f()` as an
// output-parameter write and returns "" for the null-source detector's
// semantics), this returns "*p" so the unchecked-return detector can match
// `*p = malloc(n)` against a later `if (*p == NULL)` check.
func assignedLocationText(lhs parser.Node) string {
	if lhs.Kind() == "pointer_expression" {
		return lhs.Text()
	}
	return assignedVariable(lhs)
}

// anyGlobalTarget reports whether any assigned location is NOT a function-local
// storage — i.e. a file-scope global/static, an external, or a field/subscript
// of one (`g_s.f`, `g_arr[i]`). A location is local when its base identifier is
// a function-local declaration (locals) or a parameter (params).
func anyGlobalTarget(vars []string, locals map[string]int, params map[string]bool) bool {
	for _, v := range vars {
		if v == "" {
			continue
		}
		base := v
		if b := locationBase(v); b != "" {
			base = b
		}
		if _, isLocal := locals[base]; isLocal {
			continue
		}
		if params[base] {
			continue
		}
		return true
	}
	return false
}

// locationBase returns the base variable of a field/subscript location
// (`g_s.f`, `g_arr[i]` -> "g_s"/"g_arr"), or "" for a bare identifier.
func locationBase(v string) string {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '-':
			if i+1 < len(v) && v[i+1] == '>' {
				return strings.TrimSpace(v[:i])
			}
		case '.', '[':
			return strings.TrimSpace(v[:i])
		}
	}
	return ""
}

// hasCompareOp reports whether a binary expression is an equality/relational
// comparison (==, !=, <, <=, >, >=) — the operators used to validate a return
// value (NULL / -1 / 0 / bounds).
func hasCompareOp(expr parser.Node) bool {
	for _, child := range expr.Children() {
		switch child.Kind() {
		case "==", "!=", "<", "<=", ">", ">=":
			return true
		}
	}
	return false
}

// funcReturnTypes returns a map from function name to its return type for every
// indexed function. The unchecked-return detector uses this to reject alloc-name
// heuristic matches that cannot be allocators: an allocator must return a
// pointer, so a void or scalar function whose name contains "alloc" (e.g.
// test_case_alloc, check_alloc_status) is a false positive source.
func (d *UncheckedReturnDetector) funcReturnTypes(ctx context.Context) (map[string]string, error) {
	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("unchecked return: list functions: %w", err)
	}
	types := make(map[string]string, len(funcs))
	for _, f := range funcs {
		types[f.Name] = f.ReturnType
	}
	declarations, err := d.store.ListFunctionDeclarations(ctx)
	if err != nil {
		return nil, fmt.Errorf("unchecked return: list function declarations: %w", err)
	}
	for _, dcl := range declarations {
		if _, defined := types[dcl.Name]; !defined {
			types[dcl.Name] = dcl.ReturnType
		}
	}
	return types, nil
}

// voidReturning reports whether the indexed function's declared return type is
// exactly `void` (no result to check). Used by nullSafeConsumerArg to recognise
// a void consumer whose null-safe parameter handles a NULL argument
// internally, so the source call's unchecked return is a false positive. An
// unknown/empty type stays non-void (conservative) so a missing return-type
// cannot silently widen the suppression.
func voidReturning(retTypes map[string]string, name string) bool {
	if retTypes == nil {
		return false
	}
	return strings.TrimSpace(retTypes[name]) == "void"
}

// funcSummaries bundles the cross-function facts the detector derives from
// a single pass over the indexed functions.
type funcSummaries struct {
	// passthrough names the functions whose body returns an unchecked
	// allocation result without checking it — directly (`return malloc(n)`) or
	// via an unchecked variable (`void *p = malloc(n); return p;`), or
	// transitively (`return other_wrapper(...)`). A call to such a wrapper must
	// be NULL-checked at the call site exactly like the allocator it wraps, so
	// the main detection pass treats calls to them as unchecked-return sources.
	passthrough map[string]bool
	// nullRejectParams maps a function name to the 0-based indices of the
	// parameters it rejects at entry with a failure return (see
	// entryNullRejectParams).
	nullRejectParams map[string]map[int]bool
	// paramNullSafe maps a function name to the 0-based indices of the
	// parameters that are NULL-safe in its body: a NULL argument cannot be
	// dereferenced there (see paramNullSafeParams). Superset of
	// nullRejectParams — rejecting at entry is one way to be null-safe, while
	// a positive guard `if (p != NULL) { ... }` protects the dereferences
	// without exposing a failure the caller could observe.
	paramNullSafe map[string]map[int]bool
	// fieldNullChecks maps a function name to the member paths it validates
	// against NULL at a top-level guard with a failure return (see
	// fieldNullChecksOfBody). A caller that stores an allocation into a local
	// struct field and then passes the struct to such a validator has the
	// field's NULL handled downstream.
	fieldNullChecks map[string]map[string]bool
	// nonNullReturn names the functions that never return NULL via the
	// abort-on-OOM contract: they return a variable NULL-checked with a
	// never-returning consequence (`p = alloc(); if (!p) abort(); return p;`).
	// A call to such a function has no NULL to check.
	nonNullReturn map[string]bool
}

// hasUncheckedReturnCandidate pre-scans every indexed file for the detector's
// trigger: a call to an unchecked-return API or an allocator-name function. When
// absent, the full detection is provably empty and skipped. A scan error fails
// open (returns true) so the full detector still runs.
func (d *UncheckedReturnDetector) hasUncheckedReturnCandidate(ctx context.Context) bool {
	found := false
	err := forEachFileIncludingEmpty(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		if found {
			return
		}
		for _, call := range root.FindAll("call_expression") {
			name := extractCallName(call)
			if uncheckedReturnAPIs[name] || apikb.IsAllocator(name) {
				found = true
				return
			}
		}
	})
	if err != nil {
		return true
	}
	return found
}

func (d *UncheckedReturnDetector) funcSummaries(ctx context.Context) (*funcSummaries, error) {
	// returnedSource maps a function name to the set of callee names whose result
	// it returns to its caller.
	returnedSource := make(map[string]map[string]bool)
	nullReject := make(map[string]map[int]bool)
	nullSafe := make(map[string]map[int]bool)
	fieldChecks := make(map[string]map[string]bool)

	add := func(name, callee string) {
		if callee == "" {
			return
		}
		if returnedSource[name] == nil {
			returnedSource[name] = make(map[string]bool)
		}
		returnedSource[name][callee] = true
	}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		returns := root.FindAll("return_statement")
		ids := root.FindAll("identifier")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		dos := root.FindAll("do_statement")
		conds := root.FindAll("conditional_expression")
		switches := root.FindAll("switch_statement")

		nameByLine := make(map[int]string, len(funcs))
		for _, f := range funcs {
			nameByLine[f.StartLine] = f.Name
		}
		for _, fnNode := range root.FindAll("function_definition") {
			name := nameByLine[fnNode.StartLine()]
			if name == "" {
				continue
			}
			if reject := entryNullRejectParams(fnNode); len(reject) > 0 {
				nullReject[name] = reject
			}
			if safe := paramNullSafeParams(fnNode); len(safe) > 0 {
				nullSafe[name] = safe
			}
			if checks := fieldNullChecksOfBody(fnNode); len(checks) > 0 {
				fieldChecks[name] = checks
			}
		}

		for _, f := range funcs {
			checked := d.checkedVars(ifs, whiles, fors, dos, conds, switches, calls, returns, f)

			// var -> (callee, assignLine) for `v = callee(...)`.
			calleeOfVar := make(map[string]string)
			lineOfVar := make(map[string]int)
			for _, a := range assigns {
				if !funcLineRange(f, a.StartLine()) {
					continue
				}
				if v, callee := assignCallee(a); v != "" && callee != "" {
					calleeOfVar[v] = callee
					lineOfVar[v] = a.StartLine()
				}
			}
			for _, in := range inits {
				if !funcLineRange(f, in.StartLine()) {
					continue
				}
				if v, callee := assignCallee(in); v != "" && callee != "" {
					calleeOfVar[v] = callee
					lineOfVar[v] = in.StartLine()
				}
			}

			for _, ret := range returns {
				if !funcLineRange(f, ret.StartLine()) {
					continue
				}
				if callee := returnedCalleeName(ret); callee != "" {
					add(f.Name, callee)
					continue
				}
				if v := returnedVar(ret); v != "" {
					if callee, ok := calleeOfVar[v]; ok && passthroughReturnVar(v, lineOfVar[v], f, returns, ids, checked) {
						add(f.Name, callee)
					}
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}

	// Monotone fixpoint: a function is a passthrough allocator if it returns a
	// call to an unchecked-return API, to an allocator (built-in, declared, or
	// heuristic-matched), or to another passthrough allocator. The
	// apikb.IsAllocator term covers wrappers of heuristic-matched allocators
	// (e.g. `void *w(size_t n) { return my_alloc(n); }` where my_alloc is
	// matched by the "alloc" substring heuristic but is not in
	// uncheckedReturnAPIs) — without it, w would not be recognised as a
	// passthrough and calls to w would miss the unchecked-return check.
	passthrough := make(map[string]bool)
	changed := true
	for changed {
		changed = false
		for name, callees := range returnedSource {
			if passthrough[name] || apikb.IsNonNullReturning(name) {
				continue
			}
			for callee := range callees {
				if uncheckedReturnAPIs[callee] || passthrough[callee] || apikb.IsAllocator(callee) {
					passthrough[name] = true
					changed = true
					break
				}
			}
		}
	}
	noreturn, err := collectNoreturnFuncs(ctx, d.store, d.parser, d.logger)
	if err != nil {
		return nil, err
	}
	nonNullReturn, err := collectNonNullReturns(ctx, d.store, d.parser, d.logger, noreturn)
	if err != nil {
		return nil, err
	}
	return &funcSummaries{passthrough: passthrough, nullRejectParams: nullReject, paramNullSafe: nullSafe, fieldNullChecks: fieldChecks, nonNullReturn: nonNullReturn}, nil
}

// collectNoreturnFuncs returns the set of call-target names that never return:
// standard noreturn calls (abort/exit/...), in-scan functions with no return
// statement that call a noreturn target (transitive), and global function-pointer
// variables initialized to a noreturn function (`static void (*X)(size_t) =
// oom_default;`). This is the evidence layer's twin of the planner's
// collectNoreturnCalls — the abort-on-OOM contract is resolved from the scan tree
// itself, not from a config list.
//
// The facts are collected in ONE tree pass and the fixpoint then runs in memory:
// the previous per-iteration re-scan re-read and re-walked every file once per
// fixpoint step, which on a large tree (redis: 216 files) added tens of seconds.
func collectNoreturnFuncs(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) (map[string]bool, error) {
	noreturn := make(map[string]bool, len(apikb.NoReturnCalls))
	for name := range apikb.NoReturnCalls {
		noreturn[name] = true
	}

	// noReturnFuncs: function name -> true when NONE of its definitions has a
	// return statement. callsOf: function name -> the callees it calls (merged
	// across same-name overloads). fpGlobals: function-pointer var -> init target.
	noReturnFuncs := make(map[string]bool)
	callsOf := make(map[string]map[string]bool)
	var fpGlobals []struct{ name, init string }

	err := forEachFileIncludingEmpty(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		returns := root.FindAll("return_statement")
		calls := root.FindAll("call_expression")
		for _, fn := range funcs {
			if callsOf[fn.Name] == nil {
				callsOf[fn.Name] = make(map[string]bool)
			}
			hasReturn := false
			for _, ret := range returns {
				if funcLineRange(fn, ret.StartLine()) {
					hasReturn = true
					break
				}
			}
			if !hasReturn {
				noReturnFuncs[fn.Name] = true
			}
			for _, call := range calls {
				if funcLineRange(fn, call.StartLine()) {
					callsOf[fn.Name][extractCallName(call)] = true
				}
			}
		}
		for _, decl := range root.FindAll("declaration") {
			for _, init := range decl.FindAll("init_declarator") {
				lhs, rhs, ok := init.AssignParts()
				if !ok {
					continue
				}
				name := functionPointerVarName(lhs.Text())
				if name == "" || rhs.Kind() != "identifier" {
					continue
				}
				fpGlobals = append(fpGlobals, struct{ name, init string }{name, rhs.Text()})
			}
		}
	})
	if err != nil {
		return nil, err
	}

	// In-memory monotone fixpoint: no-return functions whose callees are all
	// noreturn, and function-pointer globals pointing at a noreturn target.
	for changed := true; changed; {
		changed = false
		for name := range noReturnFuncs {
			if noreturn[name] {
				continue
			}
			for callee := range callsOf[name] {
				if noreturn[callee] {
					noreturn[name] = true
					changed = true
					break
				}
			}
		}
		for _, g := range fpGlobals {
			if !noreturn[g.name] && noreturn[g.init] {
				noreturn[g.name] = true
				changed = true
			}
		}
	}
	return noreturn, nil
}

// collectNonNullReturns returns the set of function names that never return NULL
// via the abort-on-OOM contract: they return a variable NULL-checked with a
// never-returning consequence (`p = alloc(); if (!p) oom_handler(); return p;`).
func collectNonNullReturns(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger, noreturn map[string]bool) (map[string]bool, error) {
	out := make(map[string]bool)
	err := forEachFileIncludingEmpty(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		// Hoisted once per file: the previous form re-walked the whole file AST
		// (return_statement + if_statement FindAll) per function.
		returns := root.FindAll("return_statement")
		ifStmts := root.FindAll("if_statement")
		for _, fn := range funcs {
			if out[fn.Name] {
				continue
			}
			returned := make(map[string]bool)
			for _, ret := range returns {
				if !funcLineRange(fn, ret.StartLine()) {
					continue
				}
				if v := returnedVar(ret); v != "" {
					returned[v] = true
				}
			}
			if len(returned) == 0 {
				continue
			}
			for _, ifStmt := range ifStmts {
				if !funcLineRange(fn, ifStmt.StartLine()) {
					continue
				}
				cond := ifStmt.ChildByFieldName("condition")
				if cond == nil {
					continue
				}
				vars := parser.NullCheckedVars(*cond)
				if len(vars) == 0 {
					continue
				}
				cons := ifStmt.ChildByFieldName("consequence")
				if cons == nil || !callsNoreturn(*cons, noreturn) {
					continue
				}
				for _, v := range vars {
					if returned[v] {
						out[fn.Name] = true
						break
					}
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// callsNoreturn reports whether node (a guard consequence) contains a call to a
// never-returning target.
func callsNoreturn(node parser.Node, noreturn map[string]bool) bool {
	for _, call := range node.FindAll("call_expression") {
		if noreturn[extractCallName(call)] {
			return true
		}
	}
	return false
}
