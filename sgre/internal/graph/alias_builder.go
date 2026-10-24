package graph

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// BuildInterproceduralAlias constructs the per-scan AliasGraph from the
// indexed functions. The current skeleton extracts the function-LOCAL
// aliasing shapes the UAF / double-free / memory-leak detectors already
// rely on (declaration initializer `q = p`, plain assignment `q = p`, cast
// alias `q = (T*)p`, field alias `q = p->f`, element-address `q = &p[i]`) so
// the graph answers the same questions findAliases answers today — but in a
// shared, queryable form.
//
// Cross-function shapes (return-alias `return p`, parameter-alias `f(p)`
// binding the formal to the actual, global alias `g = p`) are Phase 12
// follow-up: the builder's loop already visits every function, so adding
// those rules is an additive change once the detector migration validates
// the function-local layer.
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
			extractFunctionAliases(g, fn, body)
		}
	}
	return g, nil
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
// alias shapes into g.
func extractFunctionAliases(g *AliasGraph, fn *db.Function, body parser.Node) {
	// Declaration initializers: `T *q = p;` / `T *q = p->f;` / `T *q = (T*)p;`.
	for _, decl := range body.FindAll("declaration") {
		for _, init := range decl.FindAll("init_declarator") {
			lhs := init.ChildByFieldName("declarator")
			rhs := init.ChildByFieldName("value")
			if lhs == nil || rhs == nil {
				continue
			}
			recordAliasFromAssign(g, fn, lhs.Text(), rhs.Text())
		}
	}
	// Plain assignments: `q = p;` / `q = (T*)p;` / `q = p->f;`.
	for _, assign := range body.FindAll("assignment_expression") {
		lhs := assign.ChildByFieldName("left")
		rhs := assign.ChildByFieldName("right")
		if lhs == nil || rhs == nil {
			continue
		}
		recordAliasFromAssign(g, fn, lhs.Text(), rhs.Text())
	}
}

// recordAliasFromAssign records an alias between lhs and rhs when rhs is a
// simple alias shape (identifier / cast of identifier / field of identifier /
// address-of-element). Anything else (arithmetic, call, literal) is not an
// alias.
func recordAliasFromAssign(g *AliasGraph, fn *db.Function, lhs, rhs string) {
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
