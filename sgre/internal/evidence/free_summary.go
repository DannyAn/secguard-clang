package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type FuncSummary struct {
	ParamDirectFrees map[int]bool
	ParamFieldFrees  map[int][]string
	GlobalFrees      []string
	ReturnStores     []string
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

func buildFuncSummaries(ctx context.Context, store db.Store, p *parser.Parser) summaryMap {
	summaries := make(summaryMap)

	forEachFile(ctx, store, p, func(file *db.File, root parser.Node, funcs []*db.Function) {
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")

		for _, f := range funcs {
			params := extractFunctionParamsFrom(funcDefs, f.StartLine)

			paramWrites, paramCondWrites := computeParamWriteStates(bodies, f, params)
			s := &FuncSummary{
				ParamDirectFrees:       make(map[int]bool),
				ParamFieldFrees:        make(map[int][]string),
				ParamWrites:            paramWrites,
				ParamConditionalWrites: paramCondWrites,
			}

			s.ParamDirectFrees, s.ParamFieldFrees = computeParamFrees(bodies, f, params)

			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				if extractCallName(call) != "free" {
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

			if len(s.ParamDirectFrees) > 0 || len(s.ParamFieldFrees) > 0 || len(s.GlobalFrees) > 0 || len(s.ReturnStores) > 0 || len(s.ParamWrites) > 0 || len(s.ParamConditionalWrites) > 0 {
				summaries[f.Name] = s
			}
		}
	})

	return summaries
}

// computeParamWriteStates reports, per parameter index, two facts:
//
//   - every: the function writes through the pointer parameter on EVERY path to
//     exit (`*p = ...` on all paths). A caller's `&x` is always initialized.
//   - some:  the function writes through it on at least one path. When some is
//     true but every is false, the write is conditional (a failure path skips
//     it), and a caller must guard the error return before using the output.
//
// It builds the function CFG and checks whether the exit is reachable from the
// entry without passing a write-through statement; if it is reachable, some
// path skips the write.
func computeParamWriteStates(bodies map[int]parser.Node, f *db.Function, params []string) (map[int]bool, map[int]bool) {
	every := make(map[int]bool)
	some := make(map[int]bool)
	body := bodies[f.StartLine]
	if body.Kind() != "compound_statement" {
		return every, some
	}
	cfg := graph.BuildStmtCFG(body, f.EndLine)

	for idx, p := range params {
		if p == "" {
			continue
		}
		writeNodes := make(map[int]bool)
		var writeStmts []parser.Node
		for _, n := range cfg.Nodes {
			if n.Kind != "stmt" {
				continue
			}
			if directWritesParam(n.Stmt, p) {
				writeNodes[n.ID] = true
				writeStmts = append(writeStmts, n.Stmt)
			}
		}
		if len(writeNodes) == 0 {
			continue // never writes the param
		}
		some[idx] = true
		// "writes on all paths" iff there is NO path from entry to exit that
		// avoids every write node. A write guarded only by a NULL-check on the
		// pointer itself (`if (p) *p = ...`) still counts as every-path: a
		// caller passing `&x` guarantees p is non-NULL, so the write happens.
		if !cfg.ReachesAvoiding(cfg.Entry, writeNodes, cfg.Exit) || allNullGuardedWrites(writeStmts, p) {
			every[idx] = true
		}
	}
	return every, some
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
// that reach the function's fall-through exit. A free on a path that RETURNS
// immediately (`if (err) { free(p); return -1; }`) is conditional: the caller
// resumes only on paths where the free did NOT happen, so propagating it would
// be a false positive (cf. gz_look freeing state->out on a malloc-failure path).
// A NULL-guard `if (p != NULL) free(p)` falls through, so it is unconditional.
func computeParamFrees(bodies map[int]parser.Node, f *db.Function, params []string) (map[int]bool, map[int][]string) {
	direct := make(map[int]bool)
	field := make(map[int][]string)
	body := bodies[f.StartLine]
	if body.Kind() != "compound_statement" {
		return direct, field
	}
	cfg := graph.BuildStmtCFG(body, f.EndLine)

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
				if directNodes[idx] == nil {
					directNodes[idx] = map[int]bool{}
				}
				directNodes[idx][n.ID] = true
			} else {
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
		if anyFreeReachesFallthrough(cfg, directNodes[idx], terminators) {
			direct[idx] = true
		}
		for fieldName, nodes := range fieldNodes[idx] {
			if anyFreeReachesFallthrough(cfg, nodes, terminators) {
				field[idx] = append(field[idx], fieldName)
			}
		}
	}
	return direct, field
}

// anyFreeReachesFallthrough reports whether any of the free nodes can reach the
// exit WITHOUT passing through a terminator (return/break/continue/goto) — i.e.
// some fall-through path frees the value.
func anyFreeReachesFallthrough(cfg *graph.StmtCFG, freeNodes map[int]bool, terminators map[int]bool) bool {
	if len(freeNodes) == 0 {
		return false
	}
	for nid := range freeNodes {
		if cfg.ReachesAvoiding(nid, terminators, cfg.Exit) {
			return true
		}
	}
	return false
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
		if child.Kind() != "call_expression" || extractCallName(child) != "free" {
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
	if len(children) >= 2 {
		baseVar := ""
		fieldName := ""
		if children[0].Kind() == "identifier" {
			baseVar = children[0].Text()
		}
		if children[1].Kind() == "field_identifier" {
			fieldName = children[1].Text()
		}
		return baseVar, fieldName
	}
	return "", ""
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
	if len(children) < 2 || children[0].Kind() != "identifier" {
		return "", ""
	}
	base := children[0].Text()
	if isConstantIndex(children[1].Text()) {
		return base, base + "[" + children[1].Text() + "]"
	}
	return base, base + "[]"
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
}

func findAliases(f *db.Function, inits, assigns []parser.Node) map[string]aliasInfo {
	aliases := make(map[string]aliasInfo)

	// Declaration initializers: `int *q = p;` / `int *q = p->f;`.
	for _, decl := range inits {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		children := decl.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		rhs := children[1]

		aliasVar := extractVarFromDeclarator(lhs)
		if aliasVar == "" {
			continue
		}
		recordAlias(aliases, aliasVar, rhs)
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
		recordAlias(aliases, lhs.Text(), children[1])
	}

	return aliases
}

// recordAlias records that aliasVar aliases the object denoted by rhs (a bare
// identifier, or a field access base.field).
func recordAlias(aliases map[string]aliasInfo, aliasVar string, rhs parser.Node) {
	if rhs.Kind() == "identifier" {
		aliases[aliasVar] = aliasInfo{baseVar: rhs.Text(), field: ""}
		return
	}
	if rhs.Kind() == "field_expression" {
		baseVar, fieldName := extractFieldAccess(rhs)
		if baseVar != "" {
			aliases[aliasVar] = aliasInfo{baseVar: baseVar, field: fieldName}
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
