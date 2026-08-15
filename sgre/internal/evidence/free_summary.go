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
}

type summaryMap map[string]*FuncSummary

func buildFuncSummaries(ctx context.Context, store db.Store, p *parser.Parser) summaryMap {
	summaries := make(summaryMap)

	forEachFile(ctx, store, p, func(file *db.File, root parser.Node, funcs []*db.Function) {
		funcDefs := root.FindAll("function_definition")
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")

		for _, f := range funcs {
			params := extractFunctionParamsFrom(funcDefs, f.StartLine)

			s := &FuncSummary{
				ParamDirectFrees: make(map[int]bool),
				ParamFieldFrees:  make(map[int][]string),
				ParamWrites:      computeParamWrites(funcDefs, f, params),
			}

			s.ParamDirectFrees, s.ParamFieldFrees = computeParamFrees(funcDefs, f, params)

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

			if len(s.ParamDirectFrees) > 0 || len(s.ParamFieldFrees) > 0 || len(s.GlobalFrees) > 0 || len(s.ReturnStores) > 0 || len(s.ParamWrites) > 0 {
				summaries[f.Name] = s
			}
		}
	})

	return summaries
}

// computeParamWrites reports, per parameter index, whether the function writes
// through that pointer parameter on EVERY path to exit. It builds the function
// CFG and checks whether the exit is reachable from the entry without passing a
// write-through statement; if it is reachable, some path skips the write.
func computeParamWrites(funcDefs []parser.Node, f *db.Function, params []string) map[int]bool {
	result := make(map[int]bool)
	body := extractFunctionBodyFrom(funcDefs, f.StartLine)
	if body.Kind() != "compound_statement" {
		return result
	}
	cfg := graph.BuildStmtCFG(body, f.EndLine)

	for idx, p := range params {
		if p == "" {
			continue
		}
		writeNodes := make(map[int]bool)
		for _, n := range cfg.Nodes {
			if n.Kind != "stmt" {
				continue
			}
			if directWritesParam(n.Stmt, p) {
				writeNodes[n.ID] = true
			}
		}
		if len(writeNodes) == 0 {
			continue // never writes the param
		}
		// "writes on all paths" iff there is NO path from entry to exit that
		// avoids every write node.
		if !cfg.ReachesAvoiding(cfg.Entry, writeNodes, cfg.Exit) {
			result[idx] = true
		}
	}
	return result
}

// computeParamFrees reports, per parameter, the whole-param and per-field frees
// that reach the function's fall-through exit. A free on a path that RETURNS
// immediately (`if (err) { free(p); return -1; }`) is conditional: the caller
// resumes only on paths where the free did NOT happen, so propagating it would
// be a false positive (cf. gz_look freeing state->out on a malloc-failure path).
// A NULL-guard `if (p != NULL) free(p)` falls through, so it is unconditional.
func computeParamFrees(funcDefs []parser.Node, f *db.Function, params []string) (map[int]bool, map[int][]string) {
	direct := make(map[int]bool)
	field := make(map[int][]string)
	body := extractFunctionBodyFrom(funcDefs, f.StartLine)
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

// extractFunctionBody returns the compound_statement body of the
// function_definition whose start line matches startLine.
func extractFunctionBodyFrom(funcDefs []parser.Node, startLine int) parser.Node {
	for _, fn := range funcDefs {
		if fn.StartLine() != startLine {
			continue
		}
		if body := fn.FindFirst("compound_statement"); body != nil {
			return *body
		}
	}
	return parser.Node{}
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

func findAliases(f *db.Function, inits []parser.Node) map[string]aliasInfo {
	aliases := make(map[string]aliasInfo)

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

		if rhs.Kind() == "identifier" {
			aliases[aliasVar] = aliasInfo{baseVar: rhs.Text(), field: ""}
		}

		if rhs.Kind() == "field_expression" {
			baseVar, fieldName := extractFieldAccess(rhs)
			if baseVar != "" {
				aliases[aliasVar] = aliasInfo{baseVar: baseVar, field: fieldName}
			}
		}
	}

	return aliases
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
