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
	declLine  int
	isArray   bool
	isPointer bool
	isStatic  bool
	// typeKind classifies the declaration's type specifier for the
	// address-of-field decision: "pointer"/"array" (declarator shape),
	// "struct"/"union"/"enum" (aggregate object in this frame), "scalar",
	// "typedef_pointer" (a typedef name aliasing a POINTER), "opaque" (a
	// typedef name whose target is not visible in the scan tree).
	typeKind string
}

func (d *StackEscapeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	typedefPointers := d.collectTypedefPointers(ctx)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
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
			locals := collectStackLocals(decls, *body, fn.StartLine, fn.EndLine, typedefPointers)

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
				if name, _, opaque, ok := stackEscapeSource(children[len(children)-1], locals); ok {
					category := "return_stack_address"
					if opaque {
						// The base's declared type is an opaque typedef, so the
						// detector cannot prove whether `&q->f` addresses this
						// frame (a local aggregate) or the pointee (a hidden
						// pointer typedef). Issue #263: auto-confirming this
						// shape produced false positives; it goes to the AI as
						// a suspected lead instead.
						category = "return_stack_address_opaque"
					}
					d.emit(ctx, fn.ID, file, ret, name, category, locals[name], &result)
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
				if name, _, _, ok := stackEscapeSource(children[1], locals); ok {
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
				if name, _, _, ok := stackEscapeSource(args[3], locals); ok {
					d.emit(ctx, fn.ID, file, call, name, "escape_via_async_arg", locals[name], &result)
				}
			}
		}
	})
	return result, err
}

// collectTypedefPointers merges the tree-wide set of typedef names that alias
// a POINTER type (`typedef struct inner *inner_ptr;`). A local declared with
// such a name is a pointer even though its declarator is a bare identifier,
// which declaratorIsPointer cannot see; without this set `&q->f` on the
// typedef-renamed view of a parameter was misread as the address of a local
// object and auto-confirmed as CWE-562 (issue #263).
func (d *StackEscapeDetector) collectTypedefPointers(ctx context.Context) map[string]bool {
	merged := make(map[string]bool)
	if err := forEachIndexedFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, tree *parser.Tree) {
		for name := range typedefPointerNames(root) {
			merged[name] = true
		}
	}); err != nil {
		if d.logger != nil {
			d.logger.Warn("stack_escape: typedef pointer collection failed; typedef-renamed pointer views may be misreported", "error", err)
		}
	}
	return merged
}

// typedefPointerNames returns the typedef names declared in this tree whose
// declarator is a pointer (`typedef T *name;`, `typedef T *name[N];`). The
// pointer_declarator is a direct child of the type_definition node.
func typedefPointerNames(root parser.Node) map[string]bool {
	out := make(map[string]bool)
	for _, def := range root.FindAll("type_definition") {
		for _, child := range def.NamedChildren() {
			if child.Kind() != "pointer_declarator" {
				continue
			}
			if name := typedefDeclaratorName(child); name != "" {
				out[name] = true
			}
		}
	}
	return out
}

// typedefDeclaratorName resolves the declared name from a typedef's
// declarator. In a typedef the name parses as a type_identifier (not an
// identifier), so declaredIdentifier — which only resolves identifiers —
// returns ""; this walker accepts both terminal kinds and descends the same
// wrapper declarators (`typedef int (*fp)(void)`).
func typedefDeclaratorName(n parser.Node) string {
	for _, c := range n.NamedChildren() {
		switch c.Kind() {
		case "identifier", "type_identifier":
			return c.Text()
		case "pointer_declarator", "array_declarator", "function_declarator":
			if name := typedefDeclaratorName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

func (d *StackEscapeDetector) emit(ctx context.Context, fnID int64, file *db.File, node parser.Node, name, category string, l stackLocal, result *DetectResult) {
	props := map[string]string{
		"variable":   name,
		"category":   category,
		"expression": node.OriginalText(),
		"origin":     fmt.Sprintf("%d:%d", l.declLine, node.StartLine()),
		"storage":    "auto",
	}
	if l.typeKind != "" {
		props["base_kind"] = l.typeKind
	}
	if emitEvent(ctx, d.store, d.logger, "STACK_ESCAPE", fnID, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()}, props) {
		result.EventsCreated++
	}
}

// collectStackLocals maps every non-static function-local object name to its
// escape-relevant shape. `static` locals are recorded (with isStatic) so the
// escape-source check can explicitly exclude them; a static object's storage
// outlives the frame, so returning its address is legal.
func collectStackLocals(decls []parser.Node, body parser.Node, fnStart, fnEnd int, typedefPointers map[string]bool) map[string]stackLocal {
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
		typeKind := declTypeKind(decl, typedefPointers)
		for _, child := range decl.NamedChildren() {
			name := declaredIdentifier(child)
			if name == "" || parser.IsCTypeKeyword(name) {
				continue
			}
			if _, seen := locals[name]; seen {
				continue
			}
			l := stackLocal{declLine: decl.StartLine(), isArray: declaratorIsArray(child), isPointer: declaratorIsPointer(child), isStatic: static, typeKind: typeKind}
			// A typedef name that aliases a pointer makes the local a pointer
			// even though its declarator is a bare identifier.
			if typeKind == "typedef_pointer" {
				l.isPointer = true
			}
			// The declarator's own shape wins over the specifier's kind when
			// both are visible (`char *p` is a pointer, `int a[4]` an array).
			if l.isPointer && typeKind != "typedef_pointer" {
				l.typeKind = "pointer"
			} else if l.isArray {
				l.typeKind = "array"
			}
			locals[name] = l
		}
	}
	return locals
}

// declTypeKind classifies a declaration's type specifier for the escape
// decision. A type_identifier (a typedef name) resolves against the
// tree-wide typedef-pointer set: a pointer alias is "typedef_pointer", any
// other typedef is "opaque" — its target may be a struct (whose member
// address DOES escape) or a pointer (whose member address does NOT), and the
// detector cannot tell from the declaration alone.
func declTypeKind(decl parser.Node, typedefPointers map[string]bool) string {
	for _, child := range decl.NamedChildren() {
		switch child.Kind() {
		case "struct_specifier":
			return "struct"
		case "union_specifier":
			return "union"
		case "enum_specifier":
			return "enum"
		case "primitive_type", "sized_type_specifier":
			return "scalar"
		case "type_identifier":
			if typedefPointers[child.Text()] {
				return "typedef_pointer"
			}
			return "opaque"
		}
	}
	return ""
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

// declaratorIsPointer reports whether a declaration child binds a POINTER
// (`char *p`, `char **pp`, `void (*fp)(void)`). It descends the same wrappers
// declaredIdentifier does so `const unsigned char *h = ...` resolves h's
// declarator to a pointer.
func declaratorIsPointer(node parser.Node) bool {
	if node.Kind() == "pointer_declarator" {
		return true
	}
	for _, c := range node.NamedChildren() {
		if declaratorIsPointer(c) {
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
//
// The fourth return marks an OPAQUE base: the address-of operand addresses a
// member/element of a local whose declared type is an opaque typedef, so the
// detector cannot prove whether the address lands in this frame (a local
// aggregate) or in the pointee (a hidden pointer typedef). Such a shape must
// not be auto-confirmed (issue #263); the caller downgrades it to a suspected
// category. A plain `&local` is never opaque — it addresses the local itself,
// which is in this frame whatever its type.
func stackEscapeSource(expr parser.Node, locals map[string]stackLocal) (name, kind string, opaque, ok bool) {
	e := stripCastParenNode(expr)
	if e.Kind() == "pointer_expression" {
		if !isAddressOfNode(e) {
			return "", "", false, false
		}
		op := addressOfOperand(e)
		if op == nil {
			return "", "", false, false
		}
		if pointerArithmeticAddressOf(*op, locals) {
			return "", "", false, false
		}
		base := baseIdentifierNode(*op)
		if base == "" {
			return "", "", false, false
		}
		if l, found := locals[base]; found && !l.isStatic {
			opv := stripCastParenNode(*op)
			memberBase := opv.Kind() == "field_expression" || opv.Kind() == "subscript_expression"
			return base, "address", memberBase && l.typeKind == "opaque", true
		}
		return "", "", false, false
	}
	if e.Kind() == "identifier" {
		name := e.Text()
		if l, found := locals[name]; found && !l.isStatic && l.isArray {
			return name, "decay", false, true
		}
	}
	return "", "", false, false
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

// pointerArithmeticAddressOf reports whether an address-of operand (`&p[i]`,
// `&p->f`) is pointer arithmetic on a local POINTER rather than the address of
// a local object. `&p[i]` equals `p + i` and `&p->f` equals `p + offsetof(f)`;
// both point into the pointee (a heap block or the caller's buffer), not into
// the current frame, so returning/storing them does NOT escape the frame. The
// operand's base must be a local pointer — `&arr[i]` on a local ARRAY is still
// an in-frame address and stays reported.
func pointerArithmeticAddressOf(op parser.Node, locals map[string]stackLocal) bool {
	op = stripCastParenNode(op)
	switch op.Kind() {
	case "subscript_expression":
		base, _, ok := subscriptBaseIndex(op)
		if !ok {
			return false
		}
		if l, found := locals[base]; found && l.isPointer {
			return true
		}
	case "field_expression":
		if isArrowOperator(op) {
			base, _ := extractFieldAccess(op)
			if l, found := locals[base]; found && l.isPointer {
				return true
			}
		}
	}
	return false
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
