package evidence

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// InvalidFreeDetector flags CWE-761: a deallocator (free/realloc and the
// project deallocator set) called on an object that was NOT obtained from an
// allocator — a stack object (`free(a)` for a local array, `free(&local)`),
// a global array (`free(g_arr)`), or a pointer INTO an object rather than its
// base (`free(&arr[5])`, `free(arr + 2)`, `free(p + 4)` for a malloc base).
//
// The argument is proven non-heap by AST shape + a local/global census + the
// same alias analysis the leak detector uses, so the planner confirms every
// shape. `free(ptr)` (a plain pointer variable) is deliberately NOT reported:
// freeing the value a pointer holds is the dominant legal idiom, and proving
// it points at non-heap storage needs points-to analysis the detector does
// not do (prefer a miss over a false positive).
type InvalidFreeDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewInvalidFreeDetector(store db.Store, p *parser.Parser, logger *log.Logger) *InvalidFreeDetector {
	return &InvalidFreeDetector{store: store, parser: p, logger: logger}
}

func (d *InvalidFreeDetector) Name() string { return "invalid_free" }

func (d *InvalidFreeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		decls := root.FindAll("declaration")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		globalArrays := collectFileScopeArrays(decls, funcs)

		for _, f := range funcs {
			fnDef := functionDefAt(funcs, root, f.StartLine)
			if fnDef == nil {
				continue
			}
			body := fnDef.FindFirst("compound_statement")
			if body == nil {
				continue
			}
			locals := collectStackLocals(decls, *body, f.StartLine, f.EndLine)
			aliases := findAliases(f, inits, assigns)
			heapVars := collectHeapVars(f, assigns, inits)

			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				callee := extractCallName(call)
				// realloc is not in the deallocator set (it ends in "alloc"), but
				// it frees the old block, so `realloc(stack_array, n)` is the F5
				// invalid-free shape.
				if !apikb.IsDeallocator(callee) && callee != "realloc" {
					continue
				}
				args := getCallArgs(call)
				if len(args) == 0 {
					continue
				}
				cat, kind, base, baseOrigin := classifyFreeArg(args[0], locals, globalArrays, aliases, heapVars, file)
				if cat == "" {
					continue
				}
				props := map[string]string{
					"category":     cat,
					"variable":     base,
					"expression":   call.OriginalText(),
					"pointee_kind": kind,
				}
				if baseOrigin != "" {
					props["base_origin"] = baseOrigin
				}
				if emitEvent(ctx, d.store, d.logger, "INVALID_FREE", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, props) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// functionDefAt returns the function_definition node whose start line matches.
func functionDefAt(funcs []*db.Function, root parser.Node, startLine int) *parser.Node {
	for _, fn := range root.FindAll("function_definition") {
		if fn.StartLine() == startLine {
			return &fn
		}
	}
	return nil
}

// collectFileScopeArrays maps file-scope array names (declared outside every
// function) to true. A `free(g_arr)` on such a name frees a global, never a
// heap block.
func collectFileScopeArrays(decls []parser.Node, funcs []*db.Function) map[string]bool {
	inFunc := func(line int) bool {
		for _, f := range funcs {
			if line >= f.StartLine && line <= f.EndLine {
				return true
			}
		}
		return false
	}
	out := make(map[string]bool)
	for _, decl := range decls {
		if inFunc(decl.StartLine()) {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if !declaratorIsArray(child) {
				continue
			}
			if name := declaredIdentifier(child); name != "" && !parser.IsCTypeKeyword(name) {
				out[name] = true
			}
		}
	}
	return out
}

// collectHeapVars maps a local variable name to the line of the allocator call
// it was assigned from (`p = malloc(n)`). It is the F4 base-resolution input:
// `free(p + 4)` is a heap-offset free only when `p` is an allocator result.
func collectHeapVars(f *db.Function, assigns, inits []parser.Node) map[string]int {
	out := make(map[string]int)
	check := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		// `int *p = malloc(16)` has a pointer_declarator LHS, not a bare
		// identifier; declaredIdentifier descends the declarator to the name.
		name := declaredIdentifier(lhs)
		if name == "" {
			return
		}
		if isMallocExpr(rhs, nil) {
			out[name] = node.StartLine()
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
	return out
}

// classifyFreeArg classifies a deallocator's first argument. It returns the
// category, the pointee kind, the base object name, and (for F4) the heap base
// origin. An empty category means "not a proven non-heap argument" (the legal
// `free(ptr)` / `free(NULL)` shapes are deliberately not reported).
func classifyFreeArg(arg parser.Node, locals map[string]stackLocal, globalArrays map[string]bool, aliases map[string]aliasInfo, heapVars map[string]int, file *db.File) (category, kind, base, baseOrigin string) {
	a := stripCastParenNode(arg)
	if a.Kind() == "null" || parser.IsNullOperand(a) {
		return "", "", "", ""
	}

	// Resolve a base name to its pointee kind: heap-offset > global-array >
	// stack. Unknown returns "" (not a proven non-heap object).
	kindOf := func(name string) string {
		if isMallocBase(name, aliases, heapVars) {
			return "heap-offset"
		}
		if globalArrays[name] {
			return "global-array"
		}
		if l, ok := locals[name]; ok && !l.isStatic {
			return "stack"
		}
		return ""
	}

	switch a.Kind() {
	case "identifier":
		name := a.Text()
		if globalArrays[name] {
			return "free_global_array", "global-array", name, ""
		}
		if l, ok := locals[name]; ok && !l.isStatic && l.isArray {
			return "free_stack_object", "stack", name, ""
		}
		return "", "", "", ""
	case "pointer_expression":
		if !isAddressOfNode(a) {
			return "", "", "", ""
		}
		op := addressOfOperand(a)
		if op == nil {
			return "", "", "", ""
		}
		return classifyAddressOfOperand(*op, kindOf, heapVars, aliases, file)
	case "binary_expression":
		// `arr + 2` / `2 + arr`: an interior pointer. The base is the identifier
		// operand; the offset must be a constant or it is still an interior
		// pointer (the AST proves it is NOT the base).
		name, ok := pointerArithBase(a)
		if !ok {
			return "", "", "", ""
		}
		if k := kindOf(name); k != "" {
			return "free_offset_pointer", k, name, heapBaseOrigin(name, aliases, heapVars, file)
		}
	}
	return "", "", "", ""
}

// classifyAddressOfOperand classifies the operand of an address-of deallocator
// argument (`free(&x)`, `free(&x.f)`, `free(&arr[i])`).
func classifyAddressOfOperand(op parser.Node, kindOf func(string) string, heapVars map[string]int, aliases map[string]aliasInfo, file *db.File) (category, kind, base, baseOrigin string) {
	o := stripCastParenNode(op)
	switch o.Kind() {
	case "identifier":
		name := o.Text()
		if k := kindOf(name); k != "" {
			// `free(&local)` / `free(&global)`: address of a non-heap object.
			cat := "free_stack_object"
			if k == "global-array" {
				cat = "free_global_array"
			}
			return cat, k, name, ""
		}
	case "field_expression":
		b, _ := extractFieldAccess(o)
		if k := kindOf(b); k != "" {
			// `free(&local.f)` / `free(&global.f)`: a member of a non-heap object.
			cat := "free_stack_object"
			if k == "global-array" {
				cat = "free_global_array"
			}
			return cat, k, b, ""
		}
	case "subscript_expression":
		b, idx, ok := subscriptBaseIndex(o)
		if !ok {
			return "", "", "", ""
		}
		if k := kindOf(b); k != "" {
			// `free(&arr[i])`: an interior pointer (mid-array or heap offset).
			_ = idx
			return "free_offset_pointer", k, b, heapBaseOrigin(b, aliases, heapVars, file)
		}
	}
	return "", "", "", ""
}

// pointerArithBase returns the identifier operand of a pointer-arithmetic
// expression (`arr + 2`, `2 + arr`) — the base of an interior pointer.
func pointerArithBase(expr parser.Node) (string, bool) {
	op := ""
	for _, c := range expr.Children() {
		switch c.Kind() {
		case "+", "-":
			op = c.Kind()
		}
	}
	if op != "+" && op != "-" {
		return "", false
	}
	named := expr.NamedChildren()
	if len(named) != 2 {
		return "", false
	}
	for _, n := range named {
		if n.Kind() == "identifier" {
			return n.Text(), true
		}
	}
	return "", false
}

func isMallocBase(name string, aliases map[string]aliasInfo, heapVars map[string]int) bool {
	if _, ok := heapVars[name]; ok {
		return true
	}
	return heapVars[terminalBaseVar(aliases, name)] != 0
}

func heapBaseOrigin(name string, aliases map[string]aliasInfo, heapVars map[string]int, file *db.File) string {
	line := heapVars[terminalBaseVar(aliases, name)]
	if line == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file.Path), line)
}
