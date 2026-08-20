package evidence

import (
	"context"
	"encoding/json"

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

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		// Precompute the non-nullable-array set ONCE per file; the previous
		// code ran root.FindAll per dereference node (O(nodes) traversals).
		nonNullable := collectNonNullableArrays(root)
		allIfs := root.FindAll("if_statement")

		memberNodes := root.FindAll("field_expression")
		// `*p` parses as a pointer_expression, not a unary_expression — the
		// previous FindAll("unary_expression") never matched a dereference and
		// silently skipped every `*p` / `*p++` deref.
		derefNodes := root.FindAll("pointer_expression")
		subscriptNodes := root.FindAll("subscript_expression")

		for _, f := range funcs {
			bounds := AnalyzeBounds(IfsInFunc(allIfs, f.StartLine, f.EndLine))
			d.detectMemberAccess(ctx, f, file, memberNodes, nonNullable, bounds, &result)
			d.detectExplicitDeref(ctx, f, file, derefNodes, nonNullable, bounds, &result)
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

func (d *DereferenceDetector) detectArraySubscript(ctx context.Context, f *db.Function, file *db.File, nodes []parser.Node, nonNullable map[string]bool, bounds *RangeFacts, result *DetectResult) {
	for _, node := range nodes {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		children := node.NamedChildren()
		if len(children) == 0 {
			continue
		}
		varName := children[0].Text()
		if bounds != nil && bounds.NonZeroAt(varName, node.StartLine()) {
			continue
		}
		d.insertDerefEvent(ctx, f, file, node, varName, node.Text(), nonNullable, result)
	}
}

func (d *DereferenceDetector) insertDerefEvent(ctx context.Context, f *db.Function, file *db.File, node parser.Node, varName, expr string, nonNullable map[string]bool, result *DetectResult) {
	locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()})
	propsMap := map[string]string{"variable": varName, "expression": expr}
	if isInsideTypeExpr(node) {
		propsMap["is_type_expr"] = "true"
	}
	if nonNullable[varName] {
		propsMap["non_nullable"] = "true"
	}
	props, _ := json.Marshal(propsMap)
	_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
		EventType:  "DEREFERENCE",
		EntityID:   f.ID,
		LocationID: locID,
		Properties: string(props),
	})
	if err == nil {
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
	children := node.NamedChildren()
	if len(children) > 0 {
		return children[0].Text()
	}
	return ""
}
