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
		// Precompute the non-nullable-array set ONCE per file; the previous
		// code ran root.FindAll per dereference node (O(nodes) traversals).
		nonNullable := collectNonNullableArrays(root)
		allIfs := root.FindAll("if_statement")
		allAssigns := root.FindAll("assignment_expression")

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
			bounds := AnalyzeBounds(IfsInFunc(allIfs, f.StartLine, f.EndLine), assignsInFunc(allAssigns, f.StartLine, f.EndLine))
			d.detectMemberAccess(ctx, f, file, memberNodes, nonNullable, bounds, &result)
			d.detectMemberAccessInErrors(ctx, f, file, errorNodes, nonNullable, bounds, &result)
			d.detectExplicitDeref(ctx, f, file, derefNodes, nonNullable, bounds, &result)
			d.detectExplicitDerefInBinary(ctx, f, file, binaryNodes, nonNullable, bounds, &result)
			d.detectArraySubscript(ctx, f, file, subscriptNodes, nonNullable, bounds, &result)
		}
	})
	return result, err
}

func (d *DereferenceDetector) detectMemberAccess(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, bounds *RangeFacts, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		text := node.Text()
		if !isArrowAccess(text) {
			continue
		}
		varName := extractPointerFromField(node)
		if bounds != nil && bounds.NonZeroAt(varName, node.StartLine()) {
			continue
		}
		d.insertDerefEvent(ctx, f, file, node, varName, text, nonNullable, result)
	}
}

// detectMemberAccessInErrors recovers `->` dereferences that a macro call site
// broke into ERROR nodes, where no field_expression exists. The bare-macro
// `do { } while(0)` form is the canonical case: `DO_BLOCK_BEGIN\n q->value = 1`
// parses as a declaration whose ERROR child carries the `q->` text, and the
// field name lands in a sibling init_declarator — so a plain FindAll over
// field_expression misses the dereference entirely.
func (d *DereferenceDetector) detectMemberAccessInErrors(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, bounds *RangeFacts, result *DetectResult) {
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
		if bounds != nil && bounds.NonZeroAt(varName, node.StartLine()) {
			continue
		}
		d.insertDerefEvent(ctx, f, file, node, varName, text, nonNullable, result)
	}
}

func (d *DereferenceDetector) detectExplicitDeref(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, bounds *RangeFacts, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		text := node.Text()
		if len(text) == 0 || text[0] != '*' {
			continue
		}
		varName := text[1:]
		if bounds != nil && bounds.NonZeroAt(varName, node.StartLine()) {
			continue
		}
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
func (d *DereferenceDetector) detectExplicitDerefInBinary(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, bounds *RangeFacts, result *DetectResult) {
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
		if bounds != nil && bounds.NonZeroAt(varName, node.StartLine()) {
			continue
		}
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

func (d *DereferenceDetector) detectArraySubscript(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, bounds *RangeFacts, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		varName := extractBaseOperand(node)
		if varName == "" {
			continue
		}
		if bounds != nil && bounds.NonZeroAt(varName, node.StartLine()) {
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
	if emitEvent(ctx, d.store, d.logger, "DEREFERENCE", f.ID, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()}, propsMap) {
		result.EventsCreated++
	}
}

// collectNonNullableArrays returns the set of array variable names in the file
// that are NOT function parameters (so they are definitely non-null). It runs
// the two traversals ONCE per file instead of once per dereference node.
func collectNonNullableArrays(root parser.Node) map[string]bool {
	params := make(map[string]bool)
	for _, param := range root.FindAll("parameter_declaration") {
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
