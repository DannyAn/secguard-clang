package evidence

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// bumpAllocatorFuncs returns the names of in-tree bump/arena allocators: a
// function whose every return is pointer arithmetic on two file-scope variables
// (`g_pool + g_off`) and whose body never calls malloc/calloc/realloc. Such an
// allocator hands back interior pointers into a pre-allocated arena; the arena
// owner releases the whole pool, so an individual result is never a per-object
// leak (issue #206 A.3).
func bumpAllocatorFuncs(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) (map[string]bool, error) {
	out := map[string]bool{}
	err := forEachFile(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)
		decls := root.FindAll("declaration")
		inits := root.FindAll("init_declarator")
		assigns := root.FindAll("assignment_expression")
		for _, f := range funcs {
			body := bodies[f.StartLine]
			if body.Kind() != "compound_statement" {
				continue
			}
			if isBumpAllocatorBody(body, extractFunctionParamsFrom(funcDefs, f.StartLine), findLocalVarsFrom(decls, f), bumpLocalAssignments(f, inits, assigns)) {
				out[f.Name] = true
			}
		}
	})
	return out, err
}

// isBumpAllocatorBody reports whether a function body is a bump allocator: no
// heap-allocation call, and every return resolves (through a single-assignment
// local) to `a + b` where both operands are non-local (file-scope) identifiers —
// pointer arithmetic into a global arena.
func isBumpAllocatorBody(body parser.Node, params []string, localVars map[string]bool, assigned map[string]parser.Node) bool {
	for _, call := range body.FindAll("call_expression") {
		switch extractCallName(call) {
		case "malloc", "calloc", "realloc", "strdup", "strndup", "getline", "getdelim":
			return false
		}
	}
	returns := body.FindAll("return_statement")
	if len(returns) == 0 {
		return false
	}
	for _, ret := range returns {
		expr := returnExprNode(ret)
		if expr == nil || !isGlobalPointerArith(resolveAssigned(*expr, assigned), params, localVars) {
			return false
		}
	}
	return true
}

// resolveAssigned follows a single-assignment local to its RHS, so `return p`
// with `void *p = g_pool + g_off;` resolves to the pointer arithmetic.
func resolveAssigned(expr parser.Node, assigned map[string]parser.Node) parser.Node {
	expr = unwrapExprNode(expr)
	for expr.Kind() == "identifier" {
		rhs, ok := assigned[expr.Text()]
		if !ok {
			return expr
		}
		expr = unwrapExprNode(rhs)
	}
	return expr
}

// bumpLocalAssignments records single assignments of locals, including pointer
// declarators (`void *p = g_pool + g_off;`), so a bump allocator's `return p`
// resolves to the global pointer arithmetic it was assigned.
func bumpLocalAssignments(f *db.Function, inits, assigns []parser.Node) map[string]parser.Node {
	out := make(map[string]parser.Node)
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		if name, rhs := declaratorInitParts(init); name != "" && rhs != nil {
			out[name] = *rhs
		}
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 || children[0].Kind() != "identifier" {
			continue
		}
		out[children[0].Text()] = unwrapExprNode(children[1])
	}
	return out
}

// declaratorInitParts returns the declared name and initializer value of an
// init_declarator, resolving a pointer/array/function declarator to its name.
func declaratorInitParts(init parser.Node) (string, *parser.Node) {
	var name string
	var rhs *parser.Node
	for _, child := range init.NamedChildren() {
		switch child.Kind() {
		case "pointer_declarator", "array_declarator", "function_declarator", "parenthesized_declarator":
			if name == "" {
				name = declaratorName(child)
			}
		case "identifier":
			if name == "" {
				name = child.Text()
			}
		case "binary_expression", "call_expression", "pointer_expression", "field_expression", "subscript_expression":
			if rhs == nil {
				v := child
				rhs = &v
			}
		}
	}
	return name, rhs
}

// isGlobalPointerArith reports whether expr is `a + b` where both operands are
// non-local identifiers (pointer arithmetic into a global arena).
func isGlobalPointerArith(expr parser.Node, params []string, localVars map[string]bool) bool {
	expr = unwrapExprNode(expr)
	if expr.Kind() != "binary_expression" || parser.BinaryOperator(expr) != "+" {
		return false
	}
	kids := expr.NamedChildren()
	if len(kids) != 2 {
		return false
	}
	return isGlobalIdent(kids[0], params, localVars) && isGlobalIdent(kids[1], params, localVars)
}

// isGlobalIdent reports whether n is a bare identifier that is neither a
// parameter nor a local (i.e. a file-scope/global variable).
func isGlobalIdent(n parser.Node, params []string, localVars map[string]bool) bool {
	n = unwrapExprNode(n)
	if n.Kind() != "identifier" {
		return false
	}
	name := n.Text()
	for _, pp := range params {
		if pp == name {
			return false
		}
	}
	return !localVars[name]
}

// callCalleeName returns the callee name of a (possibly cast-wrapped) call
// expression, or "".
func callCalleeName(expr parser.Node) string {
	for expr.Kind() == "cast_expression" {
		next := parser.Node{}
		for _, c := range expr.NamedChildren() {
			if c.Kind() == "type_descriptor" {
				continue
			}
			next = c
			break
		}
		if next.Kind() == "" {
			return ""
		}
		expr = next
	}
	if expr.Kind() != "call_expression" {
		return ""
	}
	return extractCallName(expr)
}

func allocatorReturnFuncs(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) (allocReturns map[string]bool, borrowFuncs map[string]bool, escapeFuncs map[string]map[int]bool, err error) {
	// Precise cross-function "callee takes ownership of an argument" summary.
	// Computed before the borrow check so every wrapper can see helper functions
	// defined in ANY file, not just the current translation unit.
	escapeFuncs, err = globalStoreFuncs(ctx, store, p, logger)
	if err != nil {
		return nil, nil, nil, err
	}

	returnedSource := make(map[string]map[string]bool)
	borrowFuncs = make(map[string]bool)
	add := func(name, callee string) {
		if callee == "" {
			return
		}
		if returnedSource[name] == nil {
			returnedSource[name] = make(map[string]bool)
		}
		returnedSource[name][callee] = true
	}

	err = forEachFile(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		decls := root.FindAll("declaration")
		for _, f := range funcs {
			localVars := findLocalVarsFrom(decls, f)
			calleeOfVar := make(map[string]string)
			for _, a := range assigns {
				if funcLineRange(f, a.StartLine()) {
					if v, callee := assignCallee(a); v != "" && callee != "" {
						calleeOfVar[v] = callee
					}
				}
			}
			for _, in := range inits {
				if funcLineRange(f, in.StartLine()) {
					if v, callee := assignCallee(in); v != "" && callee != "" {
						calleeOfVar[v] = callee
					}
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
					if callee, ok := calleeOfVar[v]; ok {
						// A wrapper that ESCAPES the returned pointer before
						// returning it (stores it to a global/static/field, or
						// hands it to a container) is a get-or-create-and-cache
						// BORROW: the escape target owns the block, so the
						// wrapper's callers must NOT free it. Marking it an
						// allocator would turn every `x = get_item(...)` into a
						// confirmed false-positive leak (the nlog stat-registry
						// accessor pattern).
						// Strong-evidence borrow only: field/subscript store to a
						// non-local, assign to a non-local identifier, a return, or
						// a hand-off to a helper that itself stores the argument to
						// a global (the nlog_set_mon_disk_head pattern). The
						// escape-function naming heuristic is disabled here — a real
						// allocator wrapper that calls a `_add`/`_store` helper for
						// logging must NOT be misread as a borrow (EL-03); only a
						// helper PROVEN to store its argument to a global counts.
						if len(findEscapeLines(assigns, calls, returns, nil, f, v, localVars, nil, nil, false, nil)) > 0 ||
							passesToGlobalStoreFunc(calls, f, v, escapeFuncs) {
							borrowFuncs[f.Name] = true
							continue
						}
						add(f.Name, callee)
					}
				}
			}
		}
	})
	if err != nil {
		return nil, nil, nil, err
	}

	out := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for name, callees := range returnedSource {
			if out[name] {
				continue
			}
			for callee := range callees {
				if apikb.IsAllocator(callee) || out[callee] {
					out[name] = true
					changed = true
					break
				}
			}
		}
	}
	return out, borrowFuncs, escapeFuncs, nil
}

// isBorrowCall reports whether expr is (or casts) a call to a function that
// allocatorReturnFuncs identified as a get-or-create-and-cache BORROW. Such a
// call yields a reference the global/list owns, so its caller's assignment is
// not an allocation site — reporting it would be a confirmed false-positive leak.
func isBorrowCall(expr parser.Node, borrowFuncs map[string]bool) bool {
	if len(borrowFuncs) == 0 {
		return false
	}
	if expr.Kind() == "cast_expression" {
		for _, c := range expr.NamedChildren() {
			if isBorrowCall(c, borrowFuncs) {
				return true
			}
		}
		return false
	}
	if expr.Kind() != "call_expression" {
		return false
	}
	return borrowFuncs[extractCallName(expr)]
}

// isMallocExpr reports whether expr is (or casts) a malloc/calloc/realloc call.
// Nested casts (`(int)(size_t)malloc(64)`) are unwrapped recursively. The
// implicit result-returning allocators (strdup/getcwd/...) are recognized via
// apikb.IsAllocator, and realpath(path, NULL) — which allocates only when its
// second argument is NULL — is recognized explicitly (ML-11). A callee in
// allocReturns (a wrapper function that returns an allocator result) is also an
// allocation site (the "封装成函数" pattern).
func isMallocExpr(expr parser.Node, allocReturns map[string]bool) bool {
	if expr.Kind() == "cast_expression" {
		for _, c := range expr.NamedChildren() {
			if isMallocExpr(c, allocReturns) {
				return true
			}
		}
		return false
	}
	if expr.Kind() != "call_expression" {
		return false
	}
	name := extractCallName(expr)
	if apikb.IsAllocator(name) || allocReturns[name] {
		return true
	}
	if name == "realpath" {
		args := getCallArgs(expr)
		return len(args) >= 2 && parser.IsNullOperand(args[1])
	}
	return false
}

// containsLine reports whether lines contains target.
func containsLine(lines []int, target int) bool {
	for _, l := range lines {
		if l == target {
			return true
		}
	}
	return false
}

// subtractLines returns all lines in all that are not in remove.
func subtractLines(all, remove []int) []int {
	rm := make(map[int]bool, len(remove))
	for _, l := range remove {
		rm[l] = true
	}
	out := make([]int, 0, len(all))
	for _, l := range all {
		if !rm[l] {
			out = append(out, l)
		}
	}
	return out
}

// findReturnVarLines returns the lines of return statements that hand varName to
// the caller (bare `return p` or one level of parentheses `return (p)`). These
// are transfer points, not leak points; they are fed to hasLostResource's avoid
// set so the path-sensitive analysis distinguishes a return on ONE path from a
// leak on ANOTHER.
func findReturnVarLines(varName string, returns []parser.Node, f *db.Function) []int {
	var lines []int
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		if returnReturnsVar(ret, varName) {
			lines = append(lines, ret.StartLine())
		}
	}
	return lines
}
