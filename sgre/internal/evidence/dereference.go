package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/log"
	"github.com/kongan/secguard-lite/internal/parser"
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

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("dereference: list functions: %w", err)
	}

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.Parse(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		d.detectMemberAccess(ctx, f, file, root, &result)
		d.detectExplicitDeref(ctx, f, file, root, &result)
		d.detectArraySubscript(ctx, f, file, root, &result)

		tree.Close()
	}

	return result, nil
}

func (d *DereferenceDetector) detectMemberAccess(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	nodes := root.FindAll("field_expression")
	for _, node := range nodes {
		if node.StartLine() < f.StartLine || node.StartLine() > f.EndLine {
			continue
		}
		text := node.Text()
		if !isArrowAccess(text) {
			continue
		}
		varName := extractPointerFromField(node)
		d.insertDerefEvent(ctx, f, file, root, node, varName, text, result)
	}
}

func (d *DereferenceDetector) detectExplicitDeref(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	nodes := root.FindAll("unary_expression")
	for _, node := range nodes {
		if node.StartLine() < f.StartLine || node.StartLine() > f.EndLine {
			continue
		}
		text := node.Text()
		if len(text) == 0 || text[0] != '*' {
			continue
		}
		varName := text[1:]
		d.insertDerefEvent(ctx, f, file, root, node, varName, text, result)
	}
}

func (d *DereferenceDetector) detectArraySubscript(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	nodes := root.FindAll("subscript_expression")
	for _, node := range nodes {
		if node.StartLine() < f.StartLine || node.StartLine() > f.EndLine {
			continue
		}
		children := node.NamedChildren()
		if len(children) == 0 {
			continue
		}
		varName := children[0].Text()
		d.insertDerefEvent(ctx, f, file, root, node, varName, node.Text(), result)
	}
}

func (d *DereferenceDetector) insertDerefEvent(ctx context.Context, f *db.Function, file *db.File, root, node parser.Node, varName, expr string, result *DetectResult) {
	locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()})
	propsMap := map[string]string{"variable": varName, "expression": expr}
	if isNonNullableArray(root, varName) {
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

func isNonNullableArray(root parser.Node, varName string) bool {
	if varName == "" {
		return false
	}
	if isFunctionParameter(root, varName) {
		return false
	}
	for _, decl := range root.FindAll("declaration") {
		for _, ad := range decl.FindAll("array_declarator") {
			if extractDeclaratorName(ad) == varName {
				return true
			}
		}
	}
	return false
}

func isFunctionParameter(root parser.Node, varName string) bool {
	for _, param := range root.FindAll("parameter_declaration") {
		for _, ad := range param.FindAll("array_declarator") {
			if extractDeclaratorName(ad) == varName {
				return true
			}
		}
		for _, pd := range param.FindAll("pointer_declarator") {
			if extractDeclaratorName(pd) == varName {
				return true
			}
		}
		for _, child := range param.NamedChildren() {
			if child.Kind() == "identifier" && child.Text() == varName {
				return true
			}
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
