package evidence

import (
	"context"
	"sort"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// findLocalVars returns the names of variables declared inside the function.
func findLocalVarsFrom(decls []parser.Node, f *db.Function) map[string]bool {
	locals := make(map[string]bool)
	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		// An `extern` declaration (`extern int *g;`) names an external object, and
		// a `static` local has static storage duration — both live outside the
		// call's lifetime, so a pointer stored into them escapes ownership rather
		// than leaking (ML-09 extended to the static-cache idiom, e.g.
		// `static iconv_t g; g = iconv_open(...)`). The previous code collected
		// every in-function declaration as local, so `g = p` for an extern/static
		// object was misread as a local store and reported as a leak.
		hasStaticStorage := false
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "storage_class_specifier" {
				if child.Text() == "extern" || child.Text() == "static" {
					hasStaticStorage = true
				}
			}
		}
		if hasStaticStorage {
			continue
		}
		for _, child := range decl.NamedChildren() {
			name := declaredIdentifier(child)
			if name != "" && !parser.IsCTypeKeyword(name) {
				locals[name] = true
			}
		}
	}
	return locals
}

// findScalarVarsFrom maps a local variable name to true when it is declared with
// a CERTAINLY-SCALAR builtin type (`bool`, `int`, `uint32_t`, `unsigned`, ...):
// a whole-variable store to it (`ret = foo_new(...)`) is a status-code assignment,
// not a heap allocation, even when the callee name triggers the zero-config
// allocator heuristic (`_new`, `remalloc`, `*_alloc`) — the dominant class of
// confirmed false positives on production repos (nlog/stat-registry accessors).
//
// A typedef'd base type (`MsgPdu p` where `MsgPdu = char **`) hides its
// pointer-ness inside the typedef, so it is NOT recorded here: the caller
// fail-opens and keeps the store as a candidate rather than silently dropping a
// real leak. Only a `primitive_type`/`sized_type_specifier` base — or a
// typedef that resolves to one (`typedef int Status`) — is treated as
// certainly-scalar; a pointer declarator (`T *p`) is never scalar. A name
// declared as a pointer anywhere in the function is dropped (block shadowing
// `int ret; { char *ret = malloc(); }`).
func findScalarVarsFrom(decls []parser.Node, f *db.Function, typedefs *typedefs) map[string]bool {
	scalars := make(map[string]bool)
	pointers := make(map[string]bool)
	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		if hasStaticStorageSpecifier(decl) {
			continue
		}
		baseScalar := hasScalarBaseType(decl, typedefs)
		for _, child := range decl.NamedChildren() {
			var declarator parser.Node
			switch child.Kind() {
			case "init_declarator":
				d := child.ChildByFieldName("declarator")
				if d == nil {
					continue
				}
				declarator = *d
			case "identifier", "pointer_declarator", "array_declarator",
				"function_declarator", "parenthesized_declarator":
				declarator = child
			default:
				continue // attribute / type-position node
			}
			name := declaredIdentifier(declarator)
			if name == "" {
				continue
			}
			if declaratorHasPointer(declarator) {
				pointers[name] = true
				continue
			}
			if baseScalar {
				scalars[name] = true
			}
		}
	}
	for name := range pointers {
		delete(scalars, name)
	}
	return scalars
}

// hasStaticStorageSpecifier reports whether a declaration carries extern/static,
// so its object has static storage duration (a pointer stored into it escapes
// ownership rather than leaking).
func hasStaticStorageSpecifier(decl parser.Node) bool {
	for _, child := range decl.NamedChildren() {
		if child.Kind() == "storage_class_specifier" {
			if child.Text() == "extern" || child.Text() == "static" {
				return true
			}
		}
	}
	return false
}

// hasScalarBaseType reports whether a declaration's base type is a certainly-scalar
// builtin (`primitive_type`/`sized_type_specifier`), or a `type_identifier` that
// resolves to one (`typedef int Status`). A typedef that hides a pointer
// (`typedef char **MsgPdu; MsgPdu p`) or a struct/union/enum base is fail-open.
func hasScalarBaseType(decl parser.Node, typedefs *typedefs) bool {
	for _, child := range decl.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "sized_type_specifier":
			return true
		case "type_identifier":
			if typedefs != nil && typedefs.resolvesToScalar(child.Text()) {
				return true
			}
		}
	}
	return false
}

// declaratorHasPointer reports whether a declarator (sub)tree declares a
// pointer-typed object: `T *p` and `void **p` are true, `T p`, `T a[4]` and a
// function declarator are false. An array of pointers (`int *a[4]`) reports true,
// which is harmless for the caller — an array can never be a whole-variable
// allocation target, and over-reporting a pointer keeps the leak candidate rather
// than silently dropping a real one.
func declaratorHasPointer(node parser.Node) bool {
	if node.Kind() == "pointer_declarator" {
		return true
	}
	for _, c := range node.NamedChildren() {
		if declaratorHasPointer(c) {
			return true
		}
	}
	return false
}

// declaredIdentifier returns the identifier a declaration child binds, descending
// pointer/array/function/parenthesized declarator wrappers (`char *p` -> "p").
// It returns "" for type-position nodes and for the initializer value, so a type
// spelling or an initializer expression is never mistaken for a local. Without
// this descent a pointer local (`char *p;` then `p = malloc()` on a later line)
// is not recognized as local, and findEscapeLines misreads the assignment as an
// escape-to-global — a silent false-negative leak.
func declaredIdentifier(node parser.Node) string {
	switch node.Kind() {
	case "identifier":
		return node.Text()
	case "pointer_declarator", "array_declarator", "function_declarator",
		"parenthesized_declarator", "init_declarator":
		for _, child := range node.NamedChildren() {
			if name := declaredIdentifier(child); name != "" {
				return name
			}
		}
	}
	return ""
}

// writeLinesFor returns, in source order, the lines where varName is the full
// left-hand side of an assignment/initializer — a write that REPLACES its value
// (`p = malloc()`, `p = q`, `p = NULL`). `p = realloc(p, n)` is excluded: it
// consumes the previous allocation rather than dropping it. A later write is an
// "overwrite": reaching one without a free in between means the previous
// allocation's pointer was lost.
func writeLinesFor(assigns, inits []parser.Node, f *db.Function, varName string) []int {
	var lines []int
	check := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		if lhs.Kind() != "identifier" || lhs.Text() != varName {
			return
		}
		if isReallocOf(rhs, varName) {
			return
		}
		lines = append(lines, node.StartLine())
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			check(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			check(i)
		}
	}
	sort.Ints(lines)
	return lines
}

// isReallocOf reports whether expr is `realloc(varName, ...)` (possibly cast or
// parenthesized).
func isReallocOf(expr parser.Node, varName string) bool {
	for expr.Kind() == "cast_expression" || expr.Kind() == "parenthesized_expression" {
		children := expr.NamedChildren()
		if len(children) == 0 {
			return false
		}
		expr = children[0]
	}
	if expr.Kind() != "call_expression" || extractCallName(expr) != "realloc" {
		return false
	}
	args := getCallArgs(expr)
	if len(args) == 0 {
		return false
	}
	return args[0].Kind() == "identifier" && args[0].Text() == varName
}

// lhsPlainVar returns the variable a direct-write LHS names: "p" for `p = ...`
// and for a declarator `*p = ...` / `int *p = ...`, and "" for a field/subscript
// write (`p->f = ...`). It distinguishes a whole-variable write from a member
// write, which matters for self-realloc detection (a `p->f = realloc(p, n)` is
// NOT a self-realloc of p).
func lhsPlainVar(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		return lhs.Text()
	case "pointer_declarator", "array_declarator", "function_declarator", "parenthesized_declarator":
		return extractVarName(lhs)
	}
	return ""
}

// findReallocConsumeLines returns the lines where realloc(varName, n) moves
// varName's block into a DIFFERENT target (`tmp = realloc(p, n)`). The old block
// is consumed on success and still reachable through p on failure, so p is not
// leaked either way — model it as a release at that line so the leak analysis
// does not report p (a realloc-into-temp is not a lost pointer).
func findReallocConsumeLines(assigns, inits []parser.Node, f *db.Function, varName string) []int {
	var lines []int
	check := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		if !isReallocOf(rhs, varName) {
			return
		}
		if lhsPlainVar(lhs) == varName {
			return // self-realloc, not a plain consume
		}
		lines = append(lines, node.StartLine())
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			check(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			check(i)
		}
	}
	return lines
}

// findSelfReallocLines returns the lines where varName is realloc'd into itself
// (`p = realloc(p, n)`). On realloc failure the OLD block leaks (the pointer is
// overwritten with NULL), the classic CWE-401 form (ML-12).
func findSelfReallocLines(assigns, inits []parser.Node, f *db.Function, varName string) []int {
	var lines []int
	check := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		if lhsPlainVar(lhs) != varName {
			return
		}
		if isReallocOf(rhs, varName) {
			lines = append(lines, node.StartLine())
		}
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			check(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			check(i)
		}
	}
	return lines
}

// rootObjectName returns the leftmost base identifier of a field/subscript/
// pointer/cast/parenthesized expression chain (`g_list->next[i]` → "g_list",
// `*out` → "out", `(T*)g_ptr` → "g_ptr"). It returns "" when the chain is not
// rooted in a bare identifier (a call, a literal, or a nested deref `**pp`).
func rootObjectName(node parser.Node) string {
	for {
		switch node.Kind() {
		case "identifier":
			return node.Text()
		case "field_expression", "subscript_expression", "pointer_expression",
			"cast_expression", "parenthesized_expression":
			children := node.NamedChildren()
			if len(children) == 0 {
				return ""
			}
			node = children[0]
		default:
			return ""
		}
	}
}

// storesParamToGlobal reports whether function f stores pointer parameter param
// (by value) into a NON-LOCAL object on some path: a global/static identifier
// (`g_head = p`), a field/subscript of a non-local base (`g_list->next = p`,
// `g_arr[i] = p`), or through a non-local pointer (`*out = p`). This is the
// precise "callee takes ownership of the argument" signal allocatorReturnFuncs
// uses to recognize a get-or-create-and-cache BORROW: a wrapper that registers
// the returned pointer into a global list via a HELPER call (the
// `nlog_set_mon_disk_head(p)` pattern) must not be marked an allocator. A store
// into a LOCAL's field (`local.f = p`) does NOT count — that storage still dies
// with f, so the caller would still own (and leak) the pointer.
func storesParamToGlobal(assigns []parser.Node, f *db.Function, param string, localVars map[string]bool) bool {
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		lhs, rhs, ok := assign.AssignParts()
		if !ok {
			continue
		}
		if argIdentifier(rhs) != param {
			continue
		}
		switch lhs.Kind() {
		case "identifier":
			if !localVars[lhs.Text()] {
				return true
			}
		case "field_expression", "subscript_expression", "pointer_expression":
			if base := rootObjectName(lhs); base != "" && !localVars[base] {
				return true
			}
		}
	}
	return false
}

// globalStoreFuncs returns, keyed by function name, the set of pointer-parameter
// indices that the function stores into a non-local object (a global/static/
// field/subscript/out-param). It is the precise cross-function complement to the
// apikb.IsEscapeFunction naming heuristic: a name like nlog_set_mon_disk_head
// matches neither the `_put`/`_store` tokens nor the configured list, but its
// body `g_mon_disk_head = entry` proves it takes ownership of its argument.
func globalStoreFuncs(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) (map[string]map[int]bool, error) {
	out := make(map[string]map[int]bool)
	err := forEachFile(ctx, store, p, logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		funcDefs := root.FindAll("function_definition")
		assigns := root.FindAll("assignment_expression")
		decls := root.FindAll("declaration")
		for _, f := range funcs {
			params := extractFunctionParamsFrom(funcDefs, f.StartLine)
			localVars := findLocalVarsFrom(decls, f)
			for idx, param := range params {
				if param == "" {
					continue
				}
				if storesParamToGlobal(assigns, f, param, localVars) {
					if out[f.Name] == nil {
						out[f.Name] = make(map[int]bool)
					}
					out[f.Name][idx] = true
				}
			}
		}
	})
	return out, err
}

// passesToGlobalStoreFunc reports whether varName is passed (as a bare
// identifier) to a call whose callee stores that argument position into a
// non-local object — i.e. the callee takes ownership of varName.
func passesToGlobalStoreFunc(calls []parser.Node, f *db.Function, varName string, escapeFuncs map[string]map[int]bool) bool {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		idxs := escapeFuncs[extractCallName(call)]
		if len(idxs) == 0 {
			continue
		}
		args := getCallArgs(call)
		for idx := range idxs {
			if idx < len(args) && argIdentifier(args[idx]) == varName {
				return true
			}
		}
	}
	return false
}

// allocatorReturnFuncs returns the set of function NAMES whose body returns an
// allocator result — either directly (`return malloc(n)`) or via a local
// (`p = malloc(n); ... return p`). This is the "封装成函数" production wrapper
// pattern (docs/req_内存分配释放典型性优化.md): each repo wraps the third-party
// allocator in its own function that NULL-checks and memset_s-initializes before
// returning the pointer. A call to such a wrapper is itself an allocation site
// even when the wrapper's name does not contain "alloc"/"malloc" (the name
// heuristic already covers the nlog_malloc/NAT_MALLOC spellings; this covers the
// custom-named ones). Unlike UncheckedReturnDetector.passthroughAllocFuncs, it
// does NOT require the pointer to be unused between the allocation and the
// return — the NULL-check + memset_s in the wrapper body uses the pointer, which
// is exactly the shape that must still count as an allocator for leak detection.
// allocatorReturnFuncs returns two name sets over the whole scan tree:
//
//   - allocReturns: functions whose body returns an allocator result (a fresh
//     allocation) that the CALLER must free — a call to one is an allocation
//     site.
//   - borrowFuncs: functions that allocate, register the pointer into a global
//     (directly or via a helper that stores its argument to a global), and
//     return the CACHED pointer — a call to one is a BORROW, not an allocation
//     (the caller must NOT free it). This second set is what suppresses the
//     name-heuristic false positive for `nlog_db_create_new_ctrl_item` (its
//     `_new` substring matches apikb.IsAllocator even though it caches).
//
