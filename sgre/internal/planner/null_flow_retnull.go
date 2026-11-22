package planner

import (
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
)

// callResultNullSources returns the possible-null sources introduced by `p = f()`
// where f is a known possibly-null-returning function. These are synthesized in
// the planner (not emitted as NULL_VALUE events) because the detector only
// recognizes a literal `return NULL`; a function that returns a possibly-null
// variable, an allocator, or another nullable callee is only discoverable via
// the RETURN edges + intra-procedural flow, which the planner owns. The origin
// carries the CALLEE NAME (not the "external_call" marker): the nullable-source
// filter reads it back to tell an in-scan callee — whose body the report can
// embed — from a genuinely external one.
func callResultNullSources(body parser.Node, retNullable map[string]retNullability) []nullSource {
	if len(retNullable) == 0 {
		return nil
	}
	var out []nullSource
	forEachAssignment(body, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" {
			return
		}
		callee := rhsCallName(rhs)
		if callee == "" || retNullable[callee] == retNotNull {
			return
		}
		src := nullSource{variable: name, line: rhs.StartLine(), origin: callee, definite: false}
		classifySynthArgs(rhs, &src)
		out = append(out, src)
	})
	return out
}

// classifySynthArgs records the call-site argument facts a
// conditional-nonnull-getter dismissal needs: identifier arguments (checked
// against the reaching analysis at the assignment line) and whether any
// argument is an opaque shape that cannot be proven non-null. An
// address-of argument (`&x`) and a string literal are always non-null; a
// parenthesized/cast wrapper is unwrapped; everything else (NULL literal,
// call result, arithmetic) marks the source unsafe to dismiss.
// synthArgKind classifies one call-site argument by its syntactic shape for
// the inter-procedural guard contracts: an identifier's nullability resolves
// against the reaching analysis, a string literal / address-of / sizeof /
// positive literal is provably non-null (and a sizeof or positive literal is
// additionally a positive length), and anything else (a NULL literal, a
// nested call, arithmetic) is opaque and keeps the source fail-open.
type synthArgKind uint8

const (
	argIdent synthArgKind = iota
	argStrLit
	argAddrOf
	argSizeof
	argPosLit
	argOther
)

// synthArgInfo is one argument's shape; name is set only for argIdent.
type synthArgInfo struct {
	name string
	kind synthArgKind
}

func classifySynthArgs(rhs parser.Node, src *nullSource) {
	if rhs.Kind() != "call_expression" {
		src.argUnsafe = true
		return
	}
	args := callArgs(rhs)
	if len(args) == 0 {
		src.argUnsafe = true
		return
	}
	for _, a := range args {
		info := synthArgInfo{kind: argOther}
		switch a.Kind() {
		case "identifier":
			if a.Text() == "NULL" {
				src.argUnsafe = true
				break
			}
			info.kind, info.name = argIdent, a.Text()
			src.argVarNames = append(src.argVarNames, a.Text())
		case "string_literal":
			info.kind = argStrLit
		case "parenthesized_expression", "cast_expression":
			kids := a.NamedChildren()
			if len(kids) == 1 && kids[0].Kind() == "identifier" && kids[0].Text() != "NULL" {
				info.kind, info.name = argIdent, kids[0].Text()
				src.argVarNames = append(src.argVarNames, kids[0].Text())
			} else {
				src.argUnsafe = true
			}
		case "unary_expression", "pointer_expression":
			if isAddressOfExpr(a) {
				info.kind = argAddrOf
			} else {
				src.argUnsafe = true
			}
		case "sizeof_expression":
			info.kind = argSizeof
		case "number_literal":
			if v, err := strconv.ParseInt(strings.TrimSpace(a.Text()), 0, 64); err == nil && v > 0 {
				info.kind = argPosLit
			} else {
				src.argUnsafe = true
			}
		default:
			src.argUnsafe = true
		}
		src.argInfo = append(src.argInfo, info)
	}
}

// isAddressOfExpr reports whether node is a unary address-of expression
// (`&x`, `&s->f`, `&arr[i]`) — a value that can never be null. tree-sitter-c
// parses both `*p` and `&x` as pointer_expression, distinguished by the
// operator token.
func isAddressOfExpr(n parser.Node) bool {
	switch n.Kind() {
	case "unary_expression", "pointer_expression":
	default:
		return false
	}
	for _, c := range n.Children() {
		if c.Kind() == "&" {
			return true
		}
	}
	return false
}

// retNullability grades HOW the pipeline knows a function can return a
// possibly-null pointer: proven (a concrete witness — a literal NULL return,
// an allocator, a known maybe-null libc API, or a callee already graded
// proven), assumed (a fail-open assumption — a pointer parameter, a field
// read, an unknown external call, an unrecognized expression), or notNull.
// Only proven may auto-confirm: an assumed source stays suspected for the AI
// so an analyzer limitation is never presented to the classifier as a
// machine proof.
type retNullability uint8

const (
	retNotNull retNullability = iota
	retNullAssumed
	retNullProven
)

// returnsNullability grades body's return-nullability: the strongest grade
// over all return expressions (proven > assumed > notNull). fnRetType is the
// enclosing function's declared return type: a bare integer zero (or a bare
// NULL identifier) in a never-null scalar return function is the integer
// zero, not a null pointer — the return-type gate.
// collectNoreturnCalls returns the set of call-target names that never return:
// the standard noreturn functions (abort/exit/...), in-scan functions whose body
// has no return statement and calls a noreturn target (transitive), and global
// function-pointer variables initialized to a noreturn function
// (`static void (*X)(size_t) = zmalloc_default_oom;`). This is how
// `if (!p) zmalloc_oom_handler(size)` (a pointer to a function that aborts)
// earns "the null path dies here" without a config entry — resolved from the
// scan tree itself.
func collectNoreturnCalls(cache *fileParseCache, funcs []*db.Function, fileByID map[int64]*db.File) map[string]bool {
	noreturn := make(map[string]bool, len(apikb.NoReturnCalls))
	for name := range apikb.NoReturnCalls {
		noreturn[name] = true
	}
	// Single-pass fact collection + in-memory monotone fixpoint. The previous
	// form re-walked every function's body AND the whole file root (the
	// declarations FindAll) on every fixpoint iteration — O(iterations x funcs
	// x AST). noReturnFuncs: funcs with no return statement; callsOf: name ->
	// callee names (merged across same-name overloads); fpGlobals: function-
	// pointer var -> init target (collected once per file).
	noReturnFuncs := make(map[string]bool)
	callsOf := make(map[string]map[string]bool)
	var fpGlobals []struct{ name, init string }
	seenFiles := make(map[int64]bool)

	for _, fn := range funcs {
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if callsOf[fn.Name] == nil {
			callsOf[fn.Name] = make(map[string]bool)
		}
		if body.Kind() == "compound_statement" && len(body.FindAll("return_statement")) == 0 {
			// A function with no return statement that calls a noreturn target
			// never returns (its only exits are noreturn calls).
			noReturnFuncs[fn.Name] = true
			for _, call := range body.FindAll("call_expression") {
				callsOf[fn.Name][callName(call)] = true
			}
		}
		// Function-pointer globals: `static void (*X)(...) = Y;` where Y is
		// noreturn makes X() noreturn. File-scoped: collect once per file.
		if !seenFiles[file.ID] && root.Kind() != "" {
			seenFiles[file.ID] = true
			for _, decl := range root.FindAll("declaration") {
				for _, init := range decl.FindAll("init_declarator") {
					lhs := init.ChildByFieldName("declarator")
					rhs := init.ChildByFieldName("value")
					if lhs == nil || rhs == nil || rhs.Kind() != "identifier" {
						continue
					}
					name := functionPointerVarName(lhs.Text())
					if name == "" {
						continue
					}
					fpGlobals = append(fpGlobals, struct{ name, init string }{name, rhs.Text()})
				}
			}
		}
	}

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
	return noreturn
}

// collectAbortOnOOM finds functions that never return NULL because their null
// path dies in a never-returning call (`p = alloc(); if (!p) oom(); return p;`).
// This is the LOCAL seed (no inter-procedural dependency) of the abort-on-OOM
// closure; the propagation — a wrapper `if (alloc() == NULL) return NULL` whose
// alloc is never-null — runs as a monotone fixpoint in the caller.
func collectAbortOnOOM(cache *fileParseCache, funcs []*db.Function, fileByID map[int64]*db.File, noreturnCalls map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for _, fn := range funcs {
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, _ := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		abortGuarded := map[string]bool{}
		for _, ifStmt := range body.FindAll("if_statement") {
			if v := abortGuardVar(ifStmt, noreturnCalls); v != "" {
				abortGuarded[v] = true
			}
		}
		hasGuardedReturn := false
		hasNullReturn := false
		for _, ret := range body.FindAll("return_statement") {
			children := ret.NamedChildren()
			if len(children) == 0 {
				continue
			}
			if isAbortGuardedReturn(children[0], abortGuarded) {
				hasGuardedReturn = true
				continue
			}
			if parser.IsNullLiteral(children[0]) {
				hasNullReturn = true
			}
		}
		if hasGuardedReturn && !hasNullReturn {
			out[fn.Name] = true
		}
	}
	return out
}

// fnReturnsNullOnlyUnderNeverNull reports whether every `return NULL` in body is
// guarded by `if (neverNullCallee() == NULL)` — i.e. the wrapper's null path is
// dead because the allocator never returns NULL (listCreate wrapping zmalloc).
func fnReturnsNullOnlyUnderNeverNull(body parser.Node, neverNull map[string]bool) bool {
	hasNull := false
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 || !parser.IsNullLiteral(children[0]) {
			continue
		}
		hasNull = true
		if !returnGuardedByNeverNull(ret, neverNull) {
			return false
		}
	}
	return hasNull
}

// returnGuardedByNeverNull reports whether ret sits directly inside an
// `if (neverNullCallee() == NULL)` guard.
func returnGuardedByNeverNull(ret parser.Node, neverNull map[string]bool) bool {
	for p := ret.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "if_statement":
			return nullGuardedNeverNullCall(*p, neverNull) != ""
		case "compound_statement":
			continue
		case "function_definition":
			return false
		}
	}
	return false
}

// functionPointerVarName pulls the variable name out of a function-pointer
// declarator text `(*zmalloc_oom_handler)(size_t)` → "zmalloc_oom_handler".
// A non-function-pointer declarator returns "".
func functionPointerVarName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 3 || s[0] != '(' || s[1] != '*' {
		return ""
	}
	s = s[2:]
	for i, c := range s {
		if c == ')' {
			return strings.TrimSpace(s[:i])
		}
	}
	return ""
}

// abortGuardVar returns the variable an `if (!v) <noreturn-call>` guard protects:
// the consequence calls a never-returning target, so the null path dies there
// and the fall-through (and any later `return v`) is non-null.
func abortGuardVar(ifStmt parser.Node, noreturnCalls map[string]bool) string {
	cond := ifStmt.ChildByFieldName("condition")
	if cond == nil {
		return ""
	}
	vars := parser.NullCheckedVars(*cond)
	if len(vars) == 0 {
		return ""
	}
	cons := ifStmt.ChildByFieldName("consequence")
	if cons == nil || !callsNoreturn(*cons, noreturnCalls) {
		return ""
	}
	return vars[0]
}

// callsNoreturn reports whether node (a guard consequence) contains a call to a
// never-returning target.
func callsNoreturn(node parser.Node, noreturnCalls map[string]bool) bool {
	for _, call := range node.FindAll("call_expression") {
		if noreturnCalls[callName(call)] {
			return true
		}
	}
	return false
}

// isAbortGuardedReturn reports whether a return expression is a bare identifier
// (or a cast/paren of one) that an `if (!v) <noreturn>` guard protects.
func isAbortGuardedReturn(expr parser.Node, abortGuarded map[string]bool) bool {
	inner := expr
	for inner.Kind() == "cast_expression" || inner.Kind() == "parenthesized_expression" {
		kids := inner.NamedChildren()
		var next parser.Node
		for _, k := range kids {
			if k.Kind() == "type_descriptor" {
				continue
			}
			next = k
			break
		}
		if next.Kind() == "" {
			break
		}
		inner = next
	}
	return inner.Kind() == "identifier" && abortGuarded[inner.Text()]
}

func returnsNullability(body parser.Node, flow *flowResult, params map[string]int, retNullable map[string]retNullability, analyzed map[string]bool, arrs *arrayBaseInfo, srcs []nullSource, fnRetType string, noreturnCalls map[string]bool, neverNull map[string]bool) retNullability {
	// abort-on-OOM contract: a returned variable guarded by `if (!v) <noreturn>`
	// is non-null at the return — the null path dies in the never-returning
	// call. This is the scan-tree resolution of the same contract
	// config [nullability.non_null_returns] declares by name (xmalloc, zmalloc,
	// ...): a wrapper `p = alloc(); if (!p) abort(); return p;` never returns
	// NULL, so a deref of its result is not a null-deref.
	abortGuarded := map[string]bool{}
	for _, ifStmt := range body.FindAll("if_statement") {
		if v := abortGuardVar(ifStmt, noreturnCalls); v != "" {
			abortGuarded[v] = true
		}
	}
	// abort-on-OOM propagation (inter-procedural): `if (alloc() == NULL) return
	// NULL` is dead when alloc never returns NULL — the return-NULL branch is
	// unreachable (listCreate wrapping zmalloc is the canonical case).
	deadReturns := map[int]bool{}
	if neverNull != nil {
		for _, ifStmt := range body.FindAll("if_statement") {
			if nullGuardedNeverNullCall(ifStmt, neverNull) == "" {
				continue
			}
			if cons := ifStmt.ChildByFieldName("consequence"); cons != nil {
				for _, ret := range cons.FindAll("return_statement") {
					children := ret.NamedChildren()
					if len(children) > 0 && parser.IsNullLiteral(children[0]) {
						deadReturns[ret.StartLine()] = true
					}
				}
			}
		}
	}
	grade := retNotNull
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		if deadReturns[ret.StartLine()] || isAbortGuardedReturn(children[0], abortGuarded) {
			continue
		}
		switch exprRetNullability(children[0], flow, params, retNullable, analyzed, arrs, ret.StartLine(), srcs, fnRetType) {
		case retNullProven:
			return retNullProven
		case retNullAssumed:
			grade = retNullAssumed
		}
	}
	return grade
}

// nullGuardedNeverNullCall returns the callee name when ifStmt's condition is a
// null comparison (`X == NULL` / `X != NULL`) whose operand X is a call (or
// `v = call()`) to a never-null function — i.e. `if (alloc() == NULL) return
// NULL` where alloc never returns NULL, so the return-NULL branch is dead.
func nullGuardedNeverNullCall(ifStmt parser.Node, neverNull map[string]bool) string {
	cond := ifStmt.ChildByFieldName("condition")
	if cond == nil {
		return ""
	}
	return neverNullCallFromOperand(*cond, neverNull)
}

func neverNullCallFromOperand(expr parser.Node, neverNull map[string]bool) string {
	if name := rhsCallName(expr); name != "" && neverNull[name] {
		return name
	}
	// Recurse into compound expressions: `(v = f())`, `((v = f()) == NULL)`,
	// an assignment whose RHS is a call, etc.
	for _, c := range expr.NamedChildren() {
		if name := neverNullCallFromOperand(c, neverNull); name != "" {
			return name
		}
	}
	return ""
}

func exprRetNullability(expr parser.Node, flow *flowResult, params map[string]int, retNullable map[string]retNullability, analyzed map[string]bool, arrs *arrayBaseInfo, line int, srcs []nullSource, fnRetType string) retNullability {
	if parser.IsNullLiteral(expr) {
		// Return-type gate: a bare zero/NULL literal in a never-null scalar
		// return function is the integer zero, not a null pointer. A
		// pointer-cast zero (`(T *)0`) keeps its null literal meaning
		// regardless of the function's declared return type.
		if apikb.IsNeverNullScalarType(fnRetType) && expr.Kind() != "cast_expression" {
			return retNotNull
		}
		return retNullProven
	}
	switch expr.Kind() {
	case "number_literal", "char_literal", "string_literal", "true", "false", "sizeof_expression":
		// Non-pointer scalars and string literals (static storage) are non-null.
		return retNotNull
	case "pointer_expression":
		// `&x` is an address (always non-null); `*p` is a deref whose pointed-to
		// value is unknown — an assumption, not a proof.
		if strings.HasPrefix(strings.TrimSpace(expr.Text()), "&") {
			return retNotNull
		}
		return retNullAssumed
	case "identifier":
		if _, isParam := params[expr.Text()]; isParam {
			return retNullAssumed
		}
		if flow != nil && flow.reaching(expr.Text(), line) {
			if variableRetStrength(srcs, expr.Text(), line, retNullable) {
				return retNullProven
			}
			return retNullAssumed
		}
		return retNotNull
	case "cast_expression", "parenthesized_expression":
		grade := retNotNull
		for _, c := range expr.NamedChildren() {
			// A cast's type_descriptor child names the TARGET TYPE, not a
			// value — recursing into it hits the fail-open default and
			// downgrades the whole cast to assumed even when the operand is a
			// provably non-null static-array base (`(T *)(g_arr + i * 8)`).
			if c.Kind() == "type_descriptor" {
				continue
			}
			// Inside a cast the operand's null-ness is fixed by the cast, not
			// the function's return type; a parenthesized wrapper preserves it.
			inner := fnRetType
			if expr.Kind() == "cast_expression" {
				inner = ""
			}
			switch exprRetNullability(c, flow, params, retNullable, analyzed, arrs, line, srcs, inner) {
			case retNullProven:
				return retNullProven
			case retNullAssumed:
				grade = retNullAssumed
			}
		}
		return grade
	case "binary_expression":
		// Pointer arithmetic on a static base (`return g_pool_var.sects + id`,
		// `return arr - 1`): the result is an address inside or one past the
		// array and can never be NULL. Only + and - are pointer arithmetic;
		// every other binary operator yields an integer, which the fail-open
		// default below keeps conservatively nullable.
		if op := parser.BinaryOperator(expr); op == "+" || op == "-" {
			children := expr.NamedChildren()
			if len(children) == 2 && (isNonNullArrayBase(children[0], arrs) || isNonNullArrayBase(children[1], arrs)) {
				return retNotNull
			}
		}
	case "call_expression":
		name := callName(expr)
		// A function the fixpoint actually analyzed resolves via its body
		// analysis (abort-on-OOM wrappers, transitive nullability) — NOT the
		// "contains malloc" name heuristic (xmalloc is an abort-on-OOM wrapper
		// that heuristic would grade nullable). `analyzed` is the caller-closure
		// (`needNames`); an in-scan function NOT in the closure falls through to
		// the fail-open default, same as an external one — never an unsound
		// "non-null because unanalyzed".
		if analyzed[name] {
			return retNullable[name]
		}
		if apikb.IsNonNullReturning(name) {
			return retNotNull
		}
		if isAllocatorCall(name) {
			return retNullProven
		}
		if apikb.IsKnownNullableReturn(name) {
			return retNullProven
		}
		return retNullAssumed // external/unknown callee: fail-open (open world)
	}
	// field_expression (e.g. `return g_space.shell_conf`, NULL-initialized),
	// subscript_expression, conditional/binary/unary — all may yield a pointer
	// and therefore may be NULL, but without a concrete witness this is an
	// assumption (fail-open), never a proof.
	return retNullAssumed
}

// variableRetStrength reports whether every null source for variable that can
// reach line is a proven-nullable origin: an explicit NULL assignment
// (definite), a declared allocator, a known maybe-null libc function, or a
// call result of a callee the fixpoint graded proven. Any other origin (an
// external_call, a caller_null, an assumed callee) downgrades to assumed —
// the conservative direction: the candidate stays suspected for the AI instead
// of auto-confirming on incomplete evidence. Only the sources on the LAST
// source line at or before line are considered, matching single-variable
// sequential reassignment; an unpositioned source cannot be ordered and is
// treated as assumed.
func variableRetStrength(srcs []nullSource, variable string, line int, retNullable map[string]retNullability) bool {
	best := 0
	var at []nullSource
	for _, s := range srcs {
		if s.variable != variable {
			continue
		}
		if s.line <= 0 {
			return false // unpositioned source: cannot grade, fail open
		}
		if s.line > line {
			continue
		}
		if s.line > best {
			best = s.line
			at = at[:0]
		}
		if s.line == best {
			at = append(at, s)
		}
	}
	if len(at) == 0 {
		return false
	}
	for _, s := range at {
		switch {
		case s.definite:
			// `p = NULL` — a concrete witness.
		case apikb.IsDeclaredAllocator(s.origin) || apikb.IsKnownNullableReturn(s.origin):
			// malloc/strchr/... — inherently maybe-null by contract.
		case s.origin != "" && retNullable[s.origin] == retNullProven:
			// Planner-synthesized `p = f()` source whose callee the fixpoint
			// graded proven.
		default:
			return false
		}
	}
	return true
}

// arrayBaseInfo is the static-array knowledge that lets exprReturnsNullable
// recognize pointer arithmetic on a static array base
// (`return g_pool_var.sects + id`) as non-null: an array lives at a fixed
// address, so base ± any offset yields an address inside (or one past) the
// array and can never be NULL.
type arrayBaseInfo struct {
	arrays      map[string]bool
	arrayFields map[string]bool
	// facts is the tree-wide fallback: an array or an array-typed field declared
	// in a header (the normal C layout) is invisible to the per-file scan above,
	// and treating it as a pointer would manufacture a null-deref candidate for
	// `hdr_array[i]`.
	facts *repofacts.Facts
}

func (a *arrayBaseInfo) isArray(name string) bool {
	if a == nil {
		return false
	}
	if a.arrays[name] {
		return true
	}
	_, ok := a.facts.GlobalArray(name)
	return ok
}

func (a *arrayBaseInfo) isArrayField(name string) bool {
	if a == nil {
		return false
	}
	if a.arrayFields[name] {
		return true
	}
	ff, ok := a.facts.FieldByName(name)
	return ok && ff.Array
}

// collectArrayBaseInfo gathers, for one function, the names that provably
// denote static arrays: array declarators at file scope (globals, including
// extern ones) or inside the function's own body, minus the function's
// parameters (an array parameter is really a caller-controlled pointer), plus
// struct field names whose visible declarations are arrays. A field name also
// declared as a non-array is dropped: the name alone does not identify the
// struct, so an ambiguous name stays fail-open (the same ambiguity guard
// findFieldTypeName uses).
func collectArrayBaseInfo(root, body parser.Node, params map[string]int, facts *repofacts.Facts) *arrayBaseInfo {
	info := &arrayBaseInfo{arrays: make(map[string]bool), arrayFields: make(map[string]bool), facts: facts}
	if root.Kind() == "" {
		return info
	}
	for _, decl := range root.FindAll("declaration") {
		// Other functions' locals must not leak their array names into this
		// function; file-scope declarations and the function's own locals are kept.
		if !nodeInsideTree(decl, body) && nodeInsideFunction(decl) {
			continue
		}
		for _, ad := range decl.FindAll("array_declarator") {
			if name := arrayBaseDeclaratorName(ad); name != "" {
				info.arrays[name] = true
			}
		}
	}
	for name := range params {
		delete(info.arrays, name)
	}
	nonArrayFields := make(map[string]bool)
	for _, fd := range root.FindAll("field_declaration") {
		ads := fd.FindAll("array_declarator")
		for _, ad := range ads {
			if name := arrayBaseDeclaratorName(ad); name != "" {
				info.arrayFields[name] = true
			}
		}
		if len(ads) == 0 {
			for _, fi := range fd.FindAll("field_identifier") {
				nonArrayFields[fi.Text()] = true
			}
		}
	}
	for name := range nonArrayFields {
		delete(info.arrayFields, name)
	}
	return info
}

// arrayBaseDeclaratorName returns the declared name of an array declarator,
// covering both plain identifiers and struct field identifiers (which
// declaratorName does not resolve).
func arrayBaseDeclaratorName(n parser.Node) string {
	switch n.Kind() {
	case "identifier", "field_identifier":
		return n.Text()
	case "pointer_declarator", "array_declarator", "function_declarator":
		for _, c := range n.NamedChildren() {
			if name := arrayBaseDeclaratorName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

// isNonNullArrayBase reports whether expr is a pointer expression whose value
// is a static address: a file/function-scoped array name, a struct field that
// is an array, an address-of, or a string literal. Such a base plus or minus
// any offset stays at or past the array — never NULL.
func isNonNullArrayBase(expr parser.Node, arrs *arrayBaseInfo) bool {
	switch expr.Kind() {
	case "identifier":
		return arrs.isArray(expr.Text())
	case "field_expression":
		for _, c := range expr.NamedChildren() {
			if c.Kind() == "field_identifier" {
				return arrs.isArrayField(c.Text())
			}
		}
		return false
	case "pointer_expression":
		return strings.HasPrefix(strings.TrimSpace(expr.Text()), "&")
	case "string_literal":
		return true
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if isNonNullArrayBase(c, arrs) {
				return true
			}
		}
		return false
	}
	return false
}

// nodeInsideTree reports whether node lies within the subtree rooted at tree.
// The walk follows node's parent chain and compares byte ranges, so a match is
// always a node on the same tree.
func nodeInsideTree(node, tree parser.Node) bool {
	if tree.Kind() == "" || node.Kind() == "" {
		return false
	}
	for p := node.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == tree.Kind() && p.StartByte() == tree.StartByte() && p.EndByte() == tree.EndByte() {
			return true
		}
	}
	return false
}

// nodeInsideFunction reports whether node sits inside any function definition,
// i.e. it is function-local rather than file-scope.
func nodeInsideFunction(node parser.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "function_definition" {
			return true
		}
	}
	return false
}

// mayReturnPointer reports whether a function body could return a pointer value.
// It is a cheap pre-filter for computeRetNullable: a return statement whose
// expression is a non-pointer literal (int/char/bool/sizeof) cannot yield a NULL
// pointer, so the function can be skipped without running the flow analysis.
// Everything else — identifiers (a pointer parameter), calls (an allocator or a
// nullable callee), casts/parens (which may wrap a pointer), field/subscript
// (a pointer member), unary/pointer/conditional/binary — is conservatively
// treated as "may return a pointer" so the filter never drops a real nullable
// returner.
func mayReturnPointer(body parser.Node) bool {
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		expr := children[0]
		if parser.IsNullLiteral(expr) {
			return true
		}
		switch expr.Kind() {
		case "number_literal", "char_literal", "true", "false", "sizeof_expression":
			continue
		default:
			return true
		}
	}
	return false
}

func isAllocatorCall(name string) bool { return apikb.IsAllocator(name) }
