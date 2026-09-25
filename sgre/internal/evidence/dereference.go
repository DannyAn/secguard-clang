package evidence

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type DereferenceDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDereferenceDetector(store db.Store, p *parser.Parser, logger *log.Logger) *DereferenceDetector {
	return &DereferenceDetector{store: store, parser: p, logger: logger}
}

func (d *DereferenceDetector) Name() string { return "dereference" }

func (d *DereferenceDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		memberNodes := root.FindAll("field_expression")
		// `*p` parses as a pointer_expression, not a unary_expression — the
		// previous FindAll("unary_expression") never matched a dereference and
		// silently skipped every `*p` / `*p++` deref.
		derefNodes := root.FindAll("pointer_expression")
		subscriptNodes := root.FindAll("subscript_expression")
		// Macro call sites (a `for`/`do` header hidden behind a `#define`) make
		// tree-sitter recover with ERROR nodes that can swallow the `->` of a
		// member access, so a dereference that is NOT a clean field_expression
		// is recovered from these ERROR nodes as well.
		errorNodes := root.FindAll("ERROR")
		// `*q = v` at a macro call site mangles into a binary_expression whose
		// `*` is misread as multiplication (see detectExplicitDerefInBinary).
		binaryNodes := root.FindAll("binary_expression")

		for _, f := range funcs {
			// Non-nullable arrays are scoped to f so a same-named pointer in a
			// sibling function is not wrongly suppressed (P5).
			nonNullable := collectNonNullableArrays(root, f)
			// Null-guard suppression is NOT done here: a dereference is always
			// emitted as a sink, and the planner's flow analysis decides whether a
			// null source reaches it through the CFG guards. Suppressing at the
			// sink would make a guard mistake unrecoverable (see the guard model).
			d.detectMemberAccess(ctx, f, file, memberNodes, nonNullable, &result)
			d.detectMemberAccessInErrors(ctx, f, file, errorNodes, nonNullable, &result)
			d.detectExplicitDeref(ctx, f, file, derefNodes, nonNullable, &result)
			d.detectExplicitDerefInBinary(ctx, f, file, binaryNodes, nonNullable, &result)
			d.detectArraySubscript(ctx, f, file, subscriptNodes, nonNullable, &result)
		}
	})
	return result, err
}

func (d *DereferenceDetector) detectMemberAccess(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		text := node.Text()
		if !isArrowAccess(text) {
			continue
		}
		varName := extractPointerFromField(node)
		d.insertDerefEvent(ctx, f, file, node, varName, text, nonNullable, result)
	}
}

// detectMemberAccessInErrors recovers `->` dereferences that a macro call site
// broke into ERROR nodes, where no field_expression exists. The bare-macro
// `do { } while(0)` form is the canonical case: `DO_BLOCK_BEGIN\n q->value = 1`
// parses as a declaration whose ERROR child carries the `q->` text, and the
// field name lands in a sibling init_declarator — so a plain FindAll over
// field_expression misses the dereference entirely.
func (d *DereferenceDetector) detectMemberAccessInErrors(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		text := node.Text()
		if !isArrowAccess(text) {
			continue
		}
		varName := pointerFromArrowError(node)
		if varName == "" {
			continue
		}
		d.insertDerefEvent(ctx, f, file, node, varName, text, nonNullable, result)
	}
}

func (d *DereferenceDetector) detectExplicitDeref(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		text := node.Text()
		if len(text) == 0 || text[0] != '*' {
			continue
		}
		varName := text[1:]
		d.insertDerefEvent(ctx, f, file, node, varName, text, nonNullable, result)
	}
}

// detectExplicitDerefInBinary recovers an explicit `*p = v` write dereference
// that a macro call site broke: `LIST_FOR_EACH(x, h)\n *q = 1` parses as
// binary_expression[*, call_expression, assignment_expression] — the `*` is
// misread as multiplication and the dereference disappears. Genuine C cannot
// produce this shape without parentheses (a bare assignment as the RHS of `*`
// would be `f() * x = 1`, an invalid assignment target; `f() * (x = 1)` would
// parenthesize the RHS into a parenthesized_expression), so this exact shape is
// safe to reinterpret as a dereference of the assignment's LHS identifier.
func (d *DereferenceDetector) detectExplicitDerefInBinary(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		if binaryOperator(node) != "*" {
			continue
		}
		children := node.NamedChildren()
		if len(children) < 2 {
			continue
		}
		if children[0].Kind() != "call_expression" || children[1].Kind() != "assignment_expression" {
			continue
		}
		lhs := children[1].NamedChildren()
		if len(lhs) == 0 || lhs[0].Kind() != "identifier" {
			continue
		}
		varName := lhs[0].Text()
		d.insertDerefEvent(ctx, f, file, node, varName, node.Text(), nonNullable, result)
	}
}

// binaryOperator returns the operator token of a binary_expression node ("*",
// "/", "%", "+", ...), or "" when there is none. The operator is an anonymous
// child, so it is read from Children() rather than NamedChildren().
func binaryOperator(n parser.Node) string {
	for _, c := range n.Children() {
		switch c.Kind() {
		case "*", "/", "%", "+", "-", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "&", "|", "^", "<<", ">>":
			return c.Kind()
		}
	}
	return ""
}

func (d *DereferenceDetector) detectArraySubscript(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		varName := extractBaseOperand(node)
		if varName == "" {
			continue
		}
		d.insertDerefEvent(ctx, f, file, node, varName, node.Text(), nonNullable, result)
	}
}

func (d *DereferenceDetector) insertDerefEvent(ctx context.Context, f *db.Function, file *db.File, node parser.Node, varName, expr string, nonNullable map[string]bool, result *DetectResult) {
	propsMap := map[string]string{"variable": varName, "expression": expr}
	if isInsideTypeExpr(node) {
		propsMap["is_type_expr"] = "true"
	}
	if nonNullable[varName] {
		propsMap["non_nullable"] = "true"
	}
	if callee := callResultDerefCallee(node); callee != "" {
		propsMap["is_call_result_deref"] = "true"
		propsMap["callee"] = callee
	}
	if emitEvent(ctx, d.store, d.logger, "DEREFERENCE", f.ID, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()}, propsMap) {
		result.EventsCreated++
	}
}

// collectNonNullableArrays returns the set of array variable names that are
// DEFINITELY non-null at a dereference inside function f: file-scope arrays
// (globals) and arrays declared inside f, minus f's own parameters. The previous
// file-scoped-by-name version let a local array in one function mark a same-named
// pointer in another function as non-nullable (a silent null-deref false
// negative), and a same-named array parameter wrongly cleared another function's
// real array (a false positive). Scoping to f fixes both directions.
func collectNonNullableArrays(root parser.Node, f *db.Function) map[string]bool {
	params := make(map[string]bool)
	for _, param := range root.FindAll("parameter_declaration") {
		if !funcLineRange(f, param.StartLine()) {
			continue // only f's own parameters can be nullable here
		}
		for _, child := range param.NamedChildren() {
			if child.Kind() == "identifier" {
				params[child.Text()] = true
			}
		}
		if n := extractDeclaratorName(param); n != "" {
			params[n] = true
		}
	}
	arrays := make(map[string]bool)
	for _, decl := range root.FindAll("declaration") {
		// Keep f's locals and file-scope globals; skip a declaration that is
		// local to some OTHER function (its name must not leak into f).
		if !funcLineRange(f, decl.StartLine()) && insideFunctionBody(decl) {
			continue
		}
		for _, ad := range decl.FindAll("array_declarator") {
			if n := extractDeclaratorName(ad); n != "" {
				arrays[n] = true
			}
		}
	}
	for name := range params {
		delete(arrays, name)
	}
	return arrays
}

// insideFunctionBody reports whether node sits (transitively) inside a
// function_definition, i.e. it is a function-local declaration rather than a
// file-scope (global) declaration.
func insideFunctionBody(node parser.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "function_definition" {
			return true
		}
	}
	return false
}

// isInsideTypeExpr reports whether node sits lexically inside a sizeof or
// alignof expression. Dereferences there (sizeof(*p), sizeof(p->field),
// sizeof(arr[0])) are compile-time type expressions, not runtime pointer
// dereferences, so they can never be a null-dereference. The dereference
// detector tags them is_type_expr=true rather than suppressing them outright,
// so the raw event stream other consumers read (interprocedural null
// propagation) is unchanged; only the null-deref filter chain drops them.
func isInsideTypeExpr(node parser.Node) bool {
	for n := &node; n != nil; n = n.Parent() {
		switch n.Kind() {
		case "sizeof_expression", "alignof_expression":
			return true
		}
	}
	return false
}

func extractDeclaratorName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
		if child.Kind() == "array_declarator" || child.Kind() == "pointer_declarator" || child.Kind() == "function_declarator" {
			return extractDeclaratorName(child)
		}
	}
	return ""
}

func isArrowAccess(text string) bool {
	for i := 0; i < len(text)-1; i++ {
		if text[i] == '-' && text[i+1] == '>' {
			return true
		}
	}
	return false
}

func extractPointerFromField(node parser.Node) string {
	return extractBaseOperand(node)
}

// extractBaseOperand returns the base operand of a field_expression or
// subscript_expression — the identifier that is dereferenced. For a clean
// `p->f` / `arr[i]` it is the first named child; at a macro call site
// tree-sitter glues the macro invocation (a call_expression) onto the access and
// buries the real base in an ERROR node (e.g. `LIST_FOR_EACH(x, h)\n q->value`
// parses as field_expression[call_expression, ERROR(identifier q),
// field_identifier]), so the base is recovered from that ERROR child. Chained
// access (`p->a->b`, `arr[i].f`) falls back to the first child's own text.
func extractBaseOperand(node parser.Node) string {
	children := node.NamedChildren()
	if len(children) == 0 {
		return ""
	}
	if children[0].Kind() == "identifier" {
		return children[0].Text()
	}
	for _, child := range children {
		if child.Kind() == "ERROR" {
			if name := firstIdentifier(child); name != "" {
				return name
			}
		}
	}
	return children[0].Text()
}

// callResultDerefCallee returns the called function name when the dereferenced
// operand is the DIRECT result of a function call — `f()->field`,
// `*f()`, `f()[i]` — and "" otherwise. Only the base operand (children[0]) is
// consulted so `a[f()]` (which dereferences a, not f()) is not misread. The
// binary_expression form (detectExplicitDerefInBinary's macro-mangled `*q = v`)
// is excluded: its children[0] is a macro call_expression, not a dereferenced
// return value. A method-call callee (`obj->m()`) yields "" because
// extractCallName only resolves identifier callees, matching the
// retNullable key scheme (function-definition names).
func callResultDerefCallee(node parser.Node) string {
	switch node.Kind() {
	case "field_expression", "subscript_expression", "pointer_expression":
	default:
		return ""
	}
	children := node.NamedChildren()
	if len(children) == 0 {
		return ""
	}
	// A macro call site glues the macro's call_expression onto the access and
	// buries the real base in an ERROR node (e.g. field_expression[
	// call_expression, ERROR(q), field_identifier]). The call_expression there
	// is the macro invocation, not a dereferenced return value — skip it so
	// the candidate keeps its intra-procedural variable attribution.
	for _, c := range children {
		if c.Kind() == "ERROR" {
			return ""
		}
	}
	if children[0].Kind() == "call_expression" {
		return extractCallName(children[0])
	}
	return ""
}

// firstIdentifier returns the first identifier descendant of node (depth-first),
// or "" when none exists. It is used to recover a pointer name from an ERROR
// node that swallowed a member access at a macro call site.
func firstIdentifier(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	for _, child := range node.NamedChildren() {
		if name := firstIdentifier(child); name != "" {
			return name
		}
	}
	return ""
}

// pointerFromArrowError recovers the pointer identifier from an ERROR node whose
// text contains a `->` (e.g. ERROR("q->") → "q"). The identifier is the operand
// immediately before the arrow.
func pointerFromArrowError(errNode parser.Node) string {
	if name := firstIdentifier(errNode); name != "" {
		return name
	}
	return ""
}
