package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type DataFlowBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDataFlowBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *DataFlowBuilder {
	return &DataFlowBuilder{store: store, parser: p, logger: logger}
}

func (b *DataFlowBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	funcs, err := b.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("data flow: list functions: %w", err)
	}

	for _, f := range funcs {
		file, _ := b.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := readFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := b.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}

		b.detectPointerDeclarations(ctx, f, tree.RootNode(), result)
		b.detectPointerAssignments(ctx, f, tree.RootNode(), result)
		b.detectPointerReturns(ctx, f, tree.RootNode(), result)

		tree.Close()
	}

	return result, nil
}

func (b *DataFlowBuilder) detectPointerDeclarations(ctx context.Context, f *db.Function, root parser.Node, result *BuildResult) {
	decls := root.FindAll("declaration")
	for _, decl := range decls {
		if decl.StartLine() < f.StartLine || decl.StartLine() > f.EndLine {
			continue
		}
		pointerDeclarators := decl.FindAll("pointer_declarator")
		for _, pd := range pointerDeclarators {
			name := extractDeclaratorName(pd)
			if name == "" {
				continue
			}
			ty := extractTypeFromDeclaration(decl)
			isHeap := isHeapAllocation(decl)
			storageClass := "auto"
			if isHeap {
				storageClass = "heap"
			}
			_, err := b.store.InsertVariable(ctx, &db.Variable{
				FunctionID:      f.ID,
				Name:            name,
				Type:            ty,
				StorageClass:    storageClass,
				DeclarationLine: decl.StartLine(),
				IsPointer:       true,
				IsNullable:      isHeap,
			})
			if err == nil {
				result.EdgesCreated++
			}
		}
	}
}

func (b *DataFlowBuilder) detectPointerAssignments(ctx context.Context, f *db.Function, root parser.Node, result *BuildResult) {
	assigns := root.FindAll("assignment_expression")
	for _, assign := range assigns {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		rhs := children[1]
		if lhs.Kind() != "identifier" {
			continue
		}
		rhsName := ""
		if rhs.Kind() == "identifier" {
			rhsName = rhs.Text()
		} else if rhs.Kind() == "call_expression" {
			rhsName = extractCallName(rhs)
		}
		if rhsName == "" {
			continue
		}

		lhsNodeID, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, lhs.Text(), assign.StartLine()))
		if err != nil {
			continue
		}
		rhsNodeID, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, rhsName, assign.StartLine()))
		if err != nil {
			continue
		}
		props, _ := json.Marshal(map[string]string{"variable": lhs.Text()})
		_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
			SrcID:      rhsNodeID,
			DstID:      lhsNodeID,
			EdgeType:   "DATA_FLOW",
			Properties: string(props),
		})
		if err == nil {
			result.EdgesCreated++
		}
	}
}

func (b *DataFlowBuilder) detectPointerReturns(ctx context.Context, f *db.Function, root parser.Node, result *BuildResult) {
	returns := root.FindAll("return_statement")
	for _, ret := range returns {
		if ret.StartLine() < f.StartLine || ret.StartLine() > f.EndLine {
			continue
		}
		for _, child := range ret.NamedChildren() {
			if child.Kind() == "identifier" {
				retNodeID, err := b.store.GetOrCreateGraphNode(ctx, "return_slot", f.ID, "")
				if err != nil {
					continue
				}
				varNodeID, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, child.Text(), ret.StartLine()))
				if err != nil {
					continue
				}
				props, _ := json.Marshal(map[string]string{"variable": child.Text()})
				_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
					SrcID:      varNodeID,
					DstID:      retNodeID,
					EdgeType:   "DATA_FLOW",
					Properties: string(props),
				})
				if err == nil {
					result.EdgesCreated++
				}
			}
		}
	}
}

func extractDeclaratorName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
		name := extractDeclaratorName(child)
		if name != "" {
			return name
		}
	}
	return ""
}

func extractTypeFromDeclaration(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "type_identifier", "sized_type_specifier":
			return child.Text() + "*"
		}
	}
	return ""
}

func isHeapAllocation(node parser.Node) bool {
	text := node.Text()
	allocators := []string{"malloc", "calloc", "realloc"}
	for _, a := range allocators {
		if strings.Contains(text, a) {
			return true
		}
	}
	return false
}
