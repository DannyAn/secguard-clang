package graph

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// BuildInterproceduralAlias constructs the per-scan AliasGraph from the
// indexed functions. It runs in two passes:
//
//  1. Function-local shapes (declaration initializer `q = p`, plain
//     assignment `q = p`, cast alias `q = (T*)p`, field alias `q = p->f`,
//     element-address `q = &p[i]`), plus per-function fact collection
//     (return-alias sources, parameter names), plus GLOBAL aliases
//     (`g = p` where g is not a local of the current function — the
//     global's AliasKey has FunctionID=0).
//  2. Cross-function shapes: `q = foo()` links q to foo's return-alias
//     sources; `foo(p)` links p to foo's corresponding parameter.
func BuildInterproceduralAlias(ctx context.Context, store db.Store, p *parser.Parser) (*AliasGraph, error) {
	g := NewAliasGraph()
	if store == nil || p == nil {
		return g, nil
	}
	fns, err := store.ListFunctions(ctx)
	if err != nil {
		return g, err
	}
	files, err := store.ListFiles(ctx)
	if err != nil {
		return g, err
	}
	fileByID := make(map[int64]*db.File, len(files))
	for _, f := range files {
		fileByID[f.ID] = f
	}
	fnByName := make(map[string]*db.Function, len(fns))
	for _, fn := range fns {
		fnByName[fn.Name] = fn
	}
	// Collect every function's local variable names once, so the global-alias
	// check below is a set lookup instead of a per-assignment DB query.
	// (The locals are derived from the function body itself in the first
	// pass, not from the db — the db's Variable table does not carry
	// declaration-line precision.)
	// One parse per file, all functions in it share the tree.
	type fileWork struct {
		root   parser.Node
		funcs  []*db.Function
		bodies map[int]parser.Node
	}
	byFile := make(map[int64]*fileWork)
	for _, fn := range fns {
		fw, ok := byFile[fn.FileID]
		if !ok {
			fw = &fileWork{bodies: make(map[int]parser.Node)}
			byFile[fn.FileID] = fw
		}
		fw.funcs = append(fw.funcs, fn)
	}
	facts := make(map[int64]*functionAliasFacts, len(fns))
	for fid, fw := range byFile {
		file := fileByID[fid]
		if file == nil {
			continue
		}
		root, bodies := parseFileBodies(p, file)
		fw.root = root
		fw.bodies = bodies
		for _, fn := range fw.funcs {
			body := fw.bodies[fn.StartLine]
			if body.Kind() != "compound_statement" {
				continue
			}
			facts[fn.ID] = &functionAliasFacts{params: paramNamesOf(body)}
			// Collect fn's local names (declarations + parameters) so a
			// `g = p` whose g is not in this set is recorded as a global
			// alias (FunctionID=0) rather than a function-local one.
			locals := collectLocalNames(body, facts[fn.ID].params)
			extractFunctionAliases(g, fn, body, facts[fn.ID], locals)
		}
	}
	// Second pass: cross-function call edges.
	for _, fw := range byFile {
		for _, fn := range fw.funcs {
			body := fw.bodies[fn.StartLine]
			if body.Kind() != "compound_statement" {
				continue
			}
			extractCallAliases(g, fn, body, fnByName, facts)
		}
	}
	return g, nil
}

// collectLocalNames returns fn's local variable names: every declaration's
// declarator identifier plus the parameter names. A name in this set is a
// function-local; a name NOT in this set on the LHS of `g = p` is a global
// (or a file-scope static), recorded with FunctionID=0.
func collectLocalNames(body parser.Node, params []string) map[string]bool {
	locals := make(map[string]bool, len(params))
	for _, p := range params {
		locals[p] = true
	}
	for _, decl := range body.FindAll("declaration") {
		for _, d := range decl.FindAll("init_declarator") {
			if dec := d.ChildByFieldName("declarator"); dec != nil {
				if name := extractIdentifierFromDeclarator(dec.Text()); name != "" {
					locals[name] = true
				}
			}
		}
		for _, d := range decl.FindAll("declarator") {
			if name := extractIdentifierFromDeclarator(d.Text()); name != "" {
				locals[name] = true
			}
		}
	}
	return locals
}

// paramNamesOf extracts fn's parameter names in order from its body (walking
// up to the function_definition's declarator → parameter_list).
func paramNamesOf(body parser.Node) []string {
	fd := body.Parent()
	if fd == nil || fd.Kind() != "function_definition" {
		return nil
	}
	decl := fd.ChildByFieldName("declarator")
	if decl == nil {
		return nil
	}
	var params parser.Node
	var findParams func(n parser.Node)
	findParams = func(n parser.Node) {
		if params.Kind() != "" {
			return
		}
		if n.Kind() == "parameter_list" {
			params = n
			return
		}
		for _, c := range n.Children() {
			findParams(c)
		}
	}
	findParams(*decl)
	if params.Kind() == "" {
		return nil
	}
	var out []string
	for _, pdecl := range params.FindAll("parameter_declaration") {
		d := pdecl.ChildByFieldName("declarator")
		if d == nil {
			continue
		}
		if name := extractIdentifierFromDeclarator(d.Text()); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// parseFileBodies parses file once and returns the root + per-function
// compound_statement bodies keyed by start line.
func parseFileBodies(p *parser.Parser, file *db.File) (parser.Node, map[int]parser.Node) {
	src, err := readFile(file.Path)
	if err != nil {
		return parser.Node{}, nil
	}
	tree, err := p.ParseCached(src, file.Path)
	if err != nil {
		return parser.Node{}, nil
	}
	root := tree.RootNode()
	bodies := make(map[int]parser.Node)
	for _, def := range root.FindAll("function_definition") {
		if body := def.FindFirst("compound_statement"); body != nil {
			bodies[def.StartLine()] = *body
		}
	}
	return root, bodies
}

// extractFunctionAliases walks fn's body and records the function-local
// alias shapes into g. It also collects fn's return-alias sources (the
// variables named in `return p;`) and parameter names, so the second pass
// (extractCallAliases) can wire cross-function edges.
func extractFunctionAliases(g *AliasGraph, fn *db.Function, body parser.Node, fnFacts *functionAliasFacts, locals map[string]bool) {
	// Declaration initializers: `T *q = p;` / `T *q = p->f;` / `T *q = (T*)p;`.
	for _, decl := range body.FindAll("declaration") {
		for _, init := range decl.FindAll("init_declarator") {
			lhs := init.ChildByFieldName("declarator")
			rhs := init.ChildByFieldName("value")
			if lhs == nil || rhs == nil {
				continue
			}
			recordAliasFromAssign(g, fn, lhs.Text(), rhs.Text(), locals)
		}
	}
	// Plain assignments: `q = p;` / `q = (T*)p;` / `q = p->f;`.
	for _, assign := range body.FindAll("assignment_expression") {
		lhs := assign.ChildByFieldName("left")
		rhs := assign.ChildByFieldName("right")
		if lhs == nil || rhs == nil {
			continue
		}
		recordAliasFromAssign(g, fn, lhs.Text(), rhs.Text(), locals)
	}
	// Return-alias sources: `return p;` marks p as fn's return-alias source.
	for _, ret := range body.FindAll("return_statement") {
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		expr := children[0]
		if expr.Kind() == "identifier" {
			fnFacts.returnSources = append(fnFacts.returnSources, expr.Text())
		}
	}
}

// functionAliasFacts collects per-function facts for the cross-function pass.
type functionAliasFacts struct {
	returnSources []string // variables named in `return p;`
	params        []string // parameter names in order
}

// extractCallAliases walks fn's body for call expressions and wires
// cross-function alias edges: `q = foo()` links q to foo's return-alias
// sources; `foo(p)` links p to foo's corresponding parameter.
func extractCallAliases(g *AliasGraph, fn *db.Function, body parser.Node, fnByName map[string]*db.Function, facts map[int64]*functionAliasFacts) {
	for _, call := range body.FindAll("call_expression") {
		callee := call.ChildByFieldName("function")
		if callee == nil || callee.Kind() != "identifier" {
			continue
		}
		calleeName := callee.Text()
		calleeFn, ok := fnByName[calleeName]
		if !ok {
			continue
		}
		calleeFacts := facts[calleeFn.ID]
		if calleeFacts == nil {
			continue
		}
		args := call.ChildByFieldName("arguments")
		if args == nil {
			continue
		}
		// Parameter aliasing: `foo(p)` links p to foo's i-th parameter.
		argList := args.NamedChildren()
		for i, arg := range argList {
			if i >= len(calleeFacts.params) {
				break
			}
			if arg.Kind() != "identifier" {
				continue
			}
			a := AliasKey{FunctionID: fn.ID, Name: arg.Text()}
			b := AliasKey{FunctionID: calleeFn.ID, Name: calleeFacts.params[i]}
			g.Add(a, b)
		}
		// Return aliasing: `q = foo()` links q to foo's return-alias sources.
		// The parent must be an assignment or init_declarator whose LHS is q.
		parent := call.Parent()
		if parent == nil {
			continue
		}
		var lhsText string
		switch parent.Kind() {
		case "assignment_expression":
			if lhs := parent.ChildByFieldName("left"); lhs != nil {
				lhsText = lhs.Text()
			}
		case "init_declarator":
			if d := parent.ChildByFieldName("declarator"); d != nil {
				lhsText = d.Text()
			}
		}
		if lhsText == "" {
			continue
		}
		name := extractIdentifierFromDeclarator(lhsText)
		if name == "" {
			continue
		}
		for _, src := range calleeFacts.returnSources {
			a := AliasKey{FunctionID: fn.ID, Name: name}
			b := AliasKey{FunctionID: calleeFn.ID, Name: src}
			g.Add(a, b)
		}
	}
}

// recordAliasFromAssign records an alias between lhs and rhs when rhs is a
// simple alias shape (identifier / cast of identifier / field of identifier /
// address-of-element). Anything else (arithmetic, call, literal) is not an
// alias.
func recordAliasFromAssign(g *AliasGraph, fn *db.Function, lhs, rhs string, locals map[string]bool) {
	// Strip a leading cast from rhs: `q = (T*)p` aliases q to p.
	base := stripCast(rhs)
	if !isSimpleAliasSource(base) {
		return
	}
	// The lhs of a declaration carries pointer stars (`*q` in `void *q = p`);
	// the alias target is the bare identifier.
	name := extractIdentifierFromDeclarator(lhs)
	if name == "" {
		return
	}
	a := AliasKey{FunctionID: fn.ID, Name: name}
	if locals != nil && !locals[name] {
		// lhs is not a local of fn — record it as a global alias.
		a = AliasKey{FunctionID: 0, Name: name}
	}
	b := AliasKey{FunctionID: fn.ID, Name: base}
	g.Add(a, b)
}

// extractIdentifierFromDeclarator pulls the bare identifier out of a
// declarator text: `*q` → `q`, `**p` → `p`, `arr[8]` → `arr`, `(*fp)` → `fp`.
// Anything else (a full expression) returns "".
func extractIdentifierFromDeclarator(s string) string {
	for len(s) > 0 && (s[0] == '*' || s[0] == '(' || s[0] == ' ') {
		if s[0] == '(' {
			// Peel one balanced paren pair.
			depth := 0
			end := -1
			for i, c := range s {
				if c == '(' {
					depth++
				} else if c == ')' {
					depth--
					if depth == 0 {
						end = i
						break
					}
				}
			}
			if end <= 0 {
				return ""
			}
			s = s[1:end]
			continue
		}
		s = s[1:]
	}
	// Truncate at `[` (array declarator) or `(` (function pointer).
	for i, c := range s {
		if c == '[' || c == '(' {
			s = s[:i]
			break
		}
	}
	if isIdentifier(s) {
		return s
	}
	return ""
}

// isSimpleAliasSource reports whether s is a name we can alias to: a plain
// identifier, a field chain rooted at an identifier (`p->f`, `p.f`), or the
// address of an element (`&p[i]`).
func isSimpleAliasSource(s string) bool {
	if s == "" {
		return false
	}
	// Plain identifier.
	if isIdentifier(s) {
		return true
	}
	// Field chain: identifier (->|.) rest.
	for i, c := range s {
		if c == '-' || c == '.' {
			return i > 0 && isIdentifier(s[:i])
		}
	}
	// Address-of-element: &name[...]
	if len(s) > 1 && s[0] == '&' {
		inner := s[1:]
		for i, c := range inner {
			if c == '[' {
				return isIdentifier(inner[:i])
			}
		}
	}
	return false
}

// isIdentifier reports whether s is a C identifier.
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// stripCast removes a leading C cast from s (`(T*)p` → `p`). It is a
// syntactic strip only; unmatched parentheses return s unchanged.
func stripCast(s string) string {
	for len(s) > 0 && s[0] == '(' {
		depth := 0
		end := -1
		for i, c := range s {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end <= 0 || end+1 >= len(s) {
			return s
		}
		s = s[end+1:]
	}
	return s
}
