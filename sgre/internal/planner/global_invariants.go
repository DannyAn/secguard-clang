package planner

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
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
	// Collect the whole-tree no-return closure (standard functions + macro
	// definitions whose body calls one) BEFORE scanning guards: an assert
	// macro defined in one header must be recognizable in every file.
	noReturnMacros := collectNoReturnMacros(files, cache)
	for _, file := range files {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		scanInvariants(root, inv, noReturnMacros)
	}
	// Reuse the already-listed files and parse cache instead of re-listing and
	// re-parsing every translation unit (PP-10).
	scanNonZeroSourceAssignments(files, cache, resolver, inv)
	return inv
}

// scanNonZeroSourceAssignments marks a field/global target as non-zero when
// ALL assignments to it are from provably non-zero sources. This is
// complementary to scanZeroGuardedAssignments: the zero-guarded pattern handles
// `if (x == 0) return; g = x;`, while this handles `g = get_count()` /
// `g = 42`. The two never conflict — a target with a zero-guarded assignment
// from a parameter (not "obviously non-zero") simply isn't marked by this pass,
// but may already be marked by the zero-guarded pass.
func scanNonZeroSourceAssignments(files []*db.File, cache *fileParseCache, resolver *returnSummaryResolver, inv *globalInvariants) {
	if resolver == nil {
		return
	}
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
		globals := collectFileGlobals(root)
		initNonZero := collectGlobalInitializers(root)
		for _, assign := range root.FindAll("assignment_expression") {
			children := assign.NamedChildren()
			if len(children) < 2 {
				continue
			}
			lhs, rhs := children[0], children[1]
			// A field chain (`g->field`) is inherently cross-function; a bare
			// identifier is an invariant only when it is a file-scope global — a
			// function-local `d = 5` in one function must not mark a same-named
			// local `d` in another function non-zero (PP-01).
			var target string
			isGlobal := false
			if lhs.Kind() == "field_expression" {
				target = normalizeTarget(lhs.Text())
			} else if lhs.Kind() == "identifier" {
				if !globals[lhs.Text()] {
					continue
				}
				target = lhs.Text()
				isGlobal = true
			} else {
				continue
			}
			info := targets[target]
			if info == nil {
				// A global whose declaration initializer is zero/absent (BSS
				// zero-init) can be zero before its first assignment, so it is not
				// an all-paths non-zero invariant (PP-05). A field has no such
				// initial state and starts as non-zero-until-proven-otherwise.
				allNonZero := true
				if isGlobal && !initNonZero[target] {
					allNonZero = false
				}
				info = &targetInfo{allNonZero: allNonZero}
				targets[target] = info
			}
			info.hasAssignment = true
			// A compound assignment (`g += k`, `g -= 100`, `g++`) is a write from
			// an unknown source, so it must reset allNonZero rather than being
			// skipped entirely (PP-04).
			if !isSimpleAssign(assign) || !isNonZeroSource(rhs, resolver) {
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

// functionRanges returns the [startLine, endLine] of every function definition
// in root, so callers can tell a file-scope declaration from a function-local one.
func functionRanges(root parser.Node) [][2]int {
	var ranges [][2]int
	for _, fn := range root.FindAll("function_definition") {
		ranges = append(ranges, [2]int{fn.StartLine(), fn.EndLine()})
	}
	return ranges
}

func inFunction(ranges [][2]int, line int) bool {
	for _, r := range ranges {
		if line >= r[0] && line <= r[1] {
			return true
		}
	}
	return false
}

// collectFileGlobals returns the set of file-scope variable names in root: names
// declared by a `declaration` that sits outside every function body. These are
// the only bare identifiers a cross-function non-zero invariant may key on.
func collectFileGlobals(root parser.Node) map[string]bool {
	globals := make(map[string]bool)
	ranges := functionRanges(root)
	for _, decl := range root.FindAll("declaration") {
		if inFunction(ranges, decl.StartLine()) {
			continue
		}
		for _, child := range decl.NamedChildren() {
			switch child.Kind() {
			case "init_declarator", "identifier", "pointer_declarator", "array_declarator",
				"function_declarator", "parenthesized_declarator":
				if name := declaredName(child); name != "" {
					globals[name] = true
				}
			}
		}
	}
	return globals
}

// collectGlobalInitializers returns, for each file-scope variable, whether its
// declaration initializer is a provably non-zero source. A variable with no
// initializer (BSS zero-init) or a zero/unknown initializer is absent, so the
// variable is treated as possibly-zero until an assignment proves otherwise.
func collectGlobalInitializers(root parser.Node) map[string]bool {
	init := make(map[string]bool)
	ranges := functionRanges(root)
	for _, decl := range root.FindAll("declaration") {
		if inFunction(ranges, decl.StartLine()) {
			continue
		}
		for _, initDecl := range decl.FindAll("init_declarator") {
			name := declaredName(initDecl)
			if name == "" {
				continue
			}
			children := initDecl.NamedChildren()
			if len(children) >= 2 && parser.NonZeroConstantValue(children[len(children)-1].Text()) {
				init[name] = true
			}
		}
	}
	return init
}

// declaredName returns the identifier a declaration child binds, descending
// pointer/array/function/parenthesized declarator wrappers (`char *p` -> "p").
func declaredName(node parser.Node) string {
	if node.Kind() == "identifier" {
		return node.Text()
	}
	for _, child := range node.NamedChildren() {
		if name := declaredName(child); name != "" {
			return name
		}
	}
	return ""
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

func scanInvariants(root parser.Node, inv *globalInvariants, noReturnMacros map[string]bool) {
	globals := collectFileGlobals(root)
	for _, fn := range root.FindAll("function_definition") {
		body := fn.FindFirst("compound_statement")
		if body == nil {
			continue
		}
		scanZeroGuardedAssignments(*body, globals, collectLocalNames(*body), inv, noReturnMacros)
	}
}

// scanZeroGuardedAssignments finds the guard patterns that establish a
// variable as non-zero on the surviving path:
//
//	if (x == 0) return/continue/break/goto; ... g = x;   -> g non-zero
//	if (x == 0) x = DEFAULT; ... g = x;                  -> g non-zero
//	if (x == 0) abort/exit/HPE_ASSERT(0); ... g = x;     -> g non-zero (a
//	    no-return consequence kills the zero path exactly like return does)
//	if (g == 0) return/abort/exit;                        -> g non-zero
//	    (a guard on the global itself needs no propagating assignment)
func scanZeroGuardedAssignments(body parser.Node, globals, locals map[string]bool, inv *globalInvariants, noReturnMacros map[string]bool) {
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
		if !exitsEarly(*consequence) && !callsNoReturn(*consequence, noReturnMacros) && !backfillsToNonZero(*consequence, guarded) {
			continue
		}
		for _, varName := range guarded {
			// A guard on the global itself proves the global non-zero on the
			// surviving path, with no propagating assignment needed. The
			// locals shadow check keeps a function-local that shadows a
			// same-named global from marking the global (PP-01 class).
			if globals[varName] && !locals[varName] {
				inv.nonZeroVars[varName] = true
			}
			recordNonZeroAssignsAfter(body, ifStmt.EndLine(), varName, inv)
		}
	}
}

// callsNoReturn reports whether a guard consequence ends in a call that never
// returns: a standard noreturn function (abort/exit/...) or a macro whose
// #define body (resolved across the whole scan tree) calls one. This is how a
// project assert macro (HPE_ASSERT) earns the same "the zero path dies here"
// semantics as an explicit return — but only when its definition actually
// aborts, never by name alone.
func callsNoReturn(consequence parser.Node, noReturnMacros map[string]bool) bool {
	for _, call := range consequence.FindAll("call_expression") {
		name := callName(call)
		if apikb.IsNoReturnCall(name) || noReturnMacros[name] {
			return true
		}
	}
	return false
}

// collectNoReturnMacros returns the names of macros (function-like or object)
// whose definition body calls a standard never-returning function, transitively
// through other macros: `#define HPE_ASSERT(x) do { if (!(x)) abort(); } while(0)`
// is no-return, and so is a macro that only forwards to HPE_ASSERT. A macro
// whose body merely logs never qualifies — a project assert's fatality is
// resolved from its #define, never assumed from its name.
func collectNoReturnMacros(files []*db.File, cache *fileParseCache) map[string]bool {
	bodies := make(map[string]string)
	for _, file := range files {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		for _, kind := range []string{"preproc_function_def", "preproc_def"} {
			for _, def := range root.FindAll(kind) {
				name, body := "", ""
				for _, child := range def.NamedChildren() {
					switch child.Kind() {
					case "identifier":
						if name == "" {
							name = child.Text()
						}
					case "preproc_arg":
						body = child.Text()
					}
				}
				if name != "" && body != "" {
					bodies[name] = body
				}
			}
		}
	}
	noReturn := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for name, body := range bodies {
			if noReturn[name] {
				continue
			}
			for callee := range apikb.NoReturnCalls {
				if macroBodyCalls(body, callee) {
					noReturn[name] = true
					changed = true
					break
				}
			}
			if !noReturn[name] {
				for callee := range noReturn {
					if macroBodyCalls(body, callee) {
						noReturn[name] = true
						changed = true
						break
					}
				}
			}
		}
	}
	return noReturn
}

// macroBodyCalls reports whether a macro body calls callee at a word boundary
// ("abort(" inside the #define text), so a name embedded in a longer
// identifier (my_abort) does not match.
func macroBodyCalls(body, callee string) bool {
	for i := 0; i+len(callee) <= len(body); i++ {
		if body[i:i+len(callee)] != callee {
			continue
		}
		if i > 0 && isIdentByte(body[i-1]) {
			continue
		}
		j := i + len(callee)
		for j < len(body) && (body[j] == ' ' || body[j] == '\t') {
			j++
		}
		if j < len(body) && body[j] == '(' {
			return true
		}
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// collectLocalNames returns the names a function body binds locally
// (declarations and parameters), so a guard on a shadowing local is never
// misattributed to a same-named file-scope global.
func collectLocalNames(body parser.Node) map[string]bool {
	locals := make(map[string]bool)
	for _, kind := range []string{"declaration", "parameter_declaration"} {
		for _, decl := range body.FindAll(kind) {
			for _, child := range decl.NamedChildren() {
				if name := declaredName(child); name != "" {
					locals[name] = true
				}
			}
		}
	}
	return locals
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
		return normalizeTarget(lhs.Text())
	}
	return ""
}

// normalizeTarget strips whitespace around the -> and . operators (and any stray
// whitespace) so a field chain spelled `graph -> gran_time` in an assignment
// matches `graph->gran_time` in a divisor (PP-09). Identifiers contain no
// whitespace, so removing it is safe.
func normalizeTarget(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// NonZero reports whether a global variable or field is proven non-zero by a
// cross-function invariant.
func (inv *globalInvariants) NonZero(name string) bool {
	return inv.nonZeroVars[normalizeTarget(name)]
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
