package graph

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type CallGraphBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

type BuildResult struct {
	EdgesCreated  int `json:"edges_created"`
	ExternalFuncs int `json:"external_funcs"`
}

func NewCallGraphBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *CallGraphBuilder {
	return &CallGraphBuilder{store: store, parser: p, logger: logger}
}

func (b *CallGraphBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	funcs, err := b.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("call graph: list functions: %w", err)
	}

	funcMap := make(map[string]int64)
	for _, f := range funcs {
		funcMap[f.Name] = f.ID
	}

	for _, f := range funcs {
		callerNodeID, err := b.store.GetOrCreateGraphNode(ctx, "function", f.ID, "")
		if err != nil {
			if b.logger != nil {
				b.logger.Warn("failed to create graph node", "function", f.Name, "error", err)
			}
			continue
		}

		file, _ := b.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}

		calls := b.extractCalls(f, file)
		for _, callName := range calls {
			if callName == "" {
				continue
			}

			var calleeNodeID int64
			if calleeID, ok := funcMap[callName]; ok {
				calleeNodeID, err = b.store.GetOrCreateGraphNode(ctx, "function", calleeID, "")
			} else {
				props, _ := json.Marshal(map[string]bool{"external": true})
				calleeNodeID, err = b.store.GetOrCreateGraphNode(ctx, "external_function", 0, string(props))
				result.ExternalFuncs++
			}
			if err != nil {
				continue
			}

			props, _ := json.Marshal(map[string]int{"call_line": f.StartLine})
			_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
				SrcID:      callerNodeID,
				DstID:      calleeNodeID,
				EdgeType:   "CALL",
				Properties: string(props),
			})
			if err != nil {
				continue
			}
			result.EdgesCreated++
		}
	}

	return result, nil
}

func (b *CallGraphBuilder) extractCalls(f *db.Function, file *db.File) []string {
	source, err := readFile(file.Path)
	if err != nil {
		return nil
	}
	tree, err := b.parser.Parse(source, file.Path)
	if err != nil {
		return nil
	}
	defer tree.Close()

	root := tree.RootNode()
	callNodes := root.FindAll("call_expression")

	var calls []string
	for _, callNode := range callNodes {
		if callNode.StartLine() < f.StartLine || callNode.StartLine() > f.EndLine {
			continue
		}
		name := extractCallName(callNode)
		if name != "" {
			calls = append(calls, name)
		}
	}
	return calls
}

func extractCallName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" || child.Kind() == "field_expression" {
			return child.Text()
		}
	}
	return ""
}
