package evidence

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// StackEscapeDetector flags CWE-562: a function that lets the address of a
// non-static local (its own stack frame) escape the frame's lifetime, either by
// returning it (`return &local;`, `return arr;` for a local array), by storing
// it into a non-local (`g_ptr = &local;`, `obj->cb_ctx = &local;`), or by
// passing it as the 4th argument of pthread_create (an async body argument).
//
// The return shape is a certain defect (AST-deterministic: the operand is a
// local of the returning function), so the planner marks it confirmed. The
// store and async-arg shapes only prove the address escapes to a live
// location, not that the target outlives the frame or that the thread reads it
// before it dies — those are suspected leads for the AI.
//
// Sound and cheap: a single pass over function definitions; the local set is
// collected once per function and the escape-source check is O(operand depth).
// A `static` local is never reported (its storage outlives the frame).
type StackEscapeDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewStackEscapeDetector(store db.Store, p *parser.Parser, logger *log.Logger) *StackEscapeDetector {
	return &StackEscapeDetector{store: store, parser: p, logger: logger}
}

func (d *StackEscapeDetector) Name() string { return "stack_escape" }

// stackLocal is a function-local object's escape-relevant shape.
type stackLocal struct {
	declLine int
	isArray  bool
	isStatic bool
}

func (d *StackEscapeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		funcDefs := root.FindAll("function_definition")
		decls := root.FindAll("declaration")
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")

		for _, fnDef := range funcDefs {
			var fn *db.Function
			for _, f := range funcs {
				if f.StartLine == fnDef.StartLine() {
					fn = f
					break
				}
			}
			if fn == nil {
				continue
			}
			body := fnDef.FindFirst("compound_statement")
			if body == nil {
				continue
			}
			locals := collectStackLocals(decls, *body, fn.StartLine, fn.EndLine)

			// M1: the address of a local escapes via return. The returned
			// expression is the last named child of the return_statement.
			for _, ret := range returns {
				if !funcLineRange(fn, ret.StartLine()) {
					continue
				}
				children := ret.NamedChildren()
				if len(children) == 0 {
					continue
				}
				if name, _, ok := stackEscapeSource(children[len(children)-1], locals); ok {
					d.emit(ctx, fn.ID, file, ret, name, "return_stack_address", locals[name], &result)
				}
			}

			// M2: the address of a local escapes via a store into a non-local
			// (a global, a heap object, or an array element of either).
			for _, assign := range assigns {
				if !funcLineRange(fn, assign.StartLine()) {
					continue
				}
				children := assign.NamedChildren()
				if len(children) < 2 {
					continue
				}
				if !isNonLocalStoreTarget(children[0], locals) {
					continue
				}
				if name, _, ok := stackEscapeSource(children[1], locals); ok {
					d.emit(ctx, fn.ID, file, assign, name, "escape_via_store", locals[name], &result)
				}
			}

			// M3: the address of a local escapes via the async registration
			// argument (pthread_create's 4th arg). The whitelist is deliberate:
			// an ordinary synchronous call `helper(&local)` is the most common
			// legal idiom and must not fire. (Config `[escape] async_registrants`
			// extension is a future follow-up.)
			for _, call := range calls {
				if !funcLineRange(fn, call.StartLine()) {
					continue
				}
				if extractCallName(call) != "pthread_create" {
					continue
				}
				args := getCallArgs(call)
				if len(args) < 4 {
					continue
				}
				if name, _, ok := stackEscapeSource(args[3], locals); ok {
					d.emit(ctx, fn.ID, file, call, name, "escape_via_async_arg", locals[name], &result)
				}
			}
		}
	})
	return result, err
}

func (d *StackEscapeDetector) emit(ctx context.Context, fnID int64, file *db.File, node parser.Node, name, category string, l stackLocal, result *DetectResult) {
	props := map[string]string{
		"variable":   name,
		"category":   category,
		"expression": node.OriginalText(),
		"origin":     fmt.Sprintf("%d:%d", l.declLine, node.StartLine()),
		"storage":    "auto",
	}
	if emitEvent(ctx, d.store, d.logger, "STACK_ESCAPE", fnID, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()}, props) {
		result.EventsCreated++
	}
}

// collectStackLocals maps every non-static function-local object name to its
// escape-relevant shape. `static` locals are recorded (with isStatic) so the
// escape-source check can explicitly exclude them; a static object's storage
// outlives the frame, so returning its address is legal.
func collectStackLocals(decls []parser.Node, body parser.Node, fnStart, fnEnd int) map[string]stackLocal {
	locals := make(map[string]stackLocal)
	for _, decl := range decls {
		if decl.StartLine() < fnStart || decl.StartLine() > fnEnd {
			continue
		}
		// A struct/union/enum specifier's field declarations are not locals;
		// their declaration node is a field_declaration, which FindAll
		// ("declaration") does not return, so the guard here is only the
		// storage-class check below.
		static := hasStaticStorageSpecifier(decl)
		for _, child := range decl.NamedChildren() {
			name := declaredIdentifier(child)
			if name == "" || parser.IsCTypeKeyword(name) {
				continue
			}
			if _, seen := locals[name]; seen {
				continue
			}
			locals[name] = stackLocal{declLine: decl.StartLine(), isArray: declaratorIsArray(child), isStatic: static}
		}
	}
	return locals
}

func declaratorIsArray(node parser.Node) bool {
	if node.Kind() == "array_declarator" {
		return true
	}
	for _, c := range node.NamedChildren() {
		if declaratorIsArray(c) {
			return true
		}
	}
	return false
}

// stackEscapeSource reports whether expr denotes an address that escapes the
// current frame: an address-of of a non-static local (`&local`, `&local.f`,
// `&arr[2]`), or a bare local array decay (`return arr;`, `g = arr;`). The
// returned kind is "address" or "decay"; both carry the same tier, but keeping
// them separate leaves the wording precise for diagnostics.
func stackEscapeSource(expr parser.Node, locals map[string]stackLocal) (name, kind string, ok bool) {
	e := stripCastParenNode(expr)
	if e.Kind() == "pointer_expression" {
		if !isAddressOfNode(e) {
			return "", "", false
		}
		op := addressOfOperand(e)
		if op == nil {
			return "", "", false
		}
		base := baseIdentifierNode(*op)
		if base == "" {
			return "", "", false
		}
		if l, found := locals[base]; found && !l.isStatic {
			return base, "address", true
		}
		return "", "", false
	}
	if e.Kind() == "identifier" {
		name := e.Text()
		if l, found := locals[name]; found && !l.isStatic && l.isArray {
			return name, "decay", true
		}
	}
	return "", "", false
}

// isNonLocalStoreTarget reports whether an assignment LHS stores into a
// location that outlives the current frame (a global, a heap pointee, or an
// element of either). A local scalar/pointer/array target is not an escape —
// both the stored address and its container die together.
func isNonLocalStoreTarget(lhs parser.Node, locals map[string]stackLocal) bool {
	l := stripCastParenNode(lhs)
	switch l.Kind() {
	case "identifier":
		_, isLocal := locals[l.Text()]
		return !isLocal
	case "field_expression":
		// `obj->f = &local` stores through a pointer (heap/global pointee) —
		// an escape regardless of where obj itself lives. `s.f = &local` on a
		// local struct does NOT escape.
		if isArrowOperator(l) {
			return true
		}
		base, _ := extractFieldAccess(l)
		_, isLocal := locals[base]
		return !isLocal
	case "subscript_expression":
		base, _, ok := subscriptBaseIndex(l)
		if !ok {
			return true
		}
		_, isLocal := locals[base]
		return !isLocal
	case "pointer_expression":
		// `*p = &local` writes through a pointer → escape.
		return true
	}
	return true
}

// stripCastParenNode strips leading cast/parenthesized wrappers so `(int*)&x`
// and `(x)` resolve to the same operand as `&x` / `x`.
func stripCastParenNode(n parser.Node) parser.Node {
	for n.Kind() == "cast_expression" || n.Kind() == "parenthesized_expression" {
		children := n.NamedChildren()
		if len(children) == 0 {
			return n
		}
		n = children[len(children)-1]
	}
	return n
}

// isAddressOfNode reports whether a pointer_expression's OWN operator is `&`
// (address-of) rather than `*` (dereference). tree-sitter-c keeps the operator
// as an anonymous child; `&local` and `*p` both parse as pointer_expression.
func isAddressOfNode(n parser.Node) bool {
	if n.Kind() != "pointer_expression" {
		return false
	}
	for _, c := range n.Children() {
		switch c.Kind() {
		case "&":
			return true
		case "*":
			return false
		}
	}
	return false
}

// addressOfOperand returns the operand of an address-of pointer_expression
// (the last named child: `local`, `s.f`, `arr[2]`).
func addressOfOperand(n parser.Node) *parser.Node {
	children := n.NamedChildren()
	if len(children) == 0 {
		return nil
	}
	c := children[len(children)-1]
	return &c
}

// baseIdentifierNode returns the base identifier of an address-of operand
// (identifier / field_expression / subscript_expression), or "" when it is not
// a plain location (a call result, a compound expression, a string literal).
func baseIdentifierNode(n parser.Node) string {
	n = stripCastParenNode(n)
	switch n.Kind() {
	case "identifier":
		return n.Text()
	case "field_expression":
		base, _ := extractFieldAccess(n)
		return base
	case "subscript_expression":
		base, _, _ := subscriptBaseIndex(n)
		return base
	}
	return ""
}
