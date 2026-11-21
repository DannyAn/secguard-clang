package evidence

import (
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// collectFileScope buckets a file's declarations into file-scope globals and
// per-function locals. Locals carry their declaration line and block end so
// same-named variables in disjoint scopes resolve to the nearest declaration,
// not a later out-of-scope shadow. Two detectors used to copy this walk.
func collectFileScope(root parser.Node, funcs []*db.Function) (map[string]string, map[int][]scopedVarDecl) {
	globals := map[string]string{}
	locals := map[int][]scopedVarDecl{}
	for _, decl := range root.FindAll("declaration") {
		base, decls := varDeclParts(decl)
		if base == "" {
			continue
		}
		line := decl.StartLine()
		owner := -1
		var ownerFn *db.Function
		for _, fn := range funcs {
			if funcLineRange(fn, line) {
				owner = fn.StartLine
				ownerFn = fn
				break
			}
		}
		end := 0
		if ownerFn != nil {
			end = declScopeEnd(decl, ownerFn)
		}
		for _, v := range decls {
			typ := base + starSuffix(v.stars)
			if owner == -1 {
				globals[v.name] = typ
			} else {
				locals[owner] = append(locals[owner], scopedVarDecl{name: v.name, typ: typ, line: line, end: end})
			}
		}
	}
	return globals, locals
}
