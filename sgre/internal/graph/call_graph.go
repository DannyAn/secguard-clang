package graph

import (
	"context"
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

	// C allows distinct static functions with the same name across files; a
	// name->single-ID map silently shadows all but the last one and would drop
	// every CALL edge into the shadowed functions (and, via call_reach, every
	// candidate in them). Track one ID per definition, mirroring interproc.go.
	funcMap := make(map[string][]int64)
	for _, f := range funcs {
		funcMap[f.Name] = append(funcMap[f.Name], f.ID)
	}

	err = forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
		callNodes := root.FindAll("call_expression")

		for _, f := range fileFuncs {
			callerNodeID, err := b.store.GetOrCreateGraphNode(ctx, "function", f.ID, "")
			if err != nil {
				if b.logger != nil {
					b.logger.Warn("failed to create graph node", "function", f.Name, "error", err)
				}
				continue
			}

			for _, callNode := range nodesInRange(callNodes, f.StartLine, f.EndLine) {
				callName := extractCallName(callNode)
				if callName == "" {
					continue
				}

				calleeIDs := funcMap[callName]
				if len(calleeIDs) == 0 {
					props := marshalProps(b.logger, "CALL", map[string]string{"name": callName, "external": "true"})
					calleeNodeID, err := b.store.GetOrCreateGraphNode(ctx, "external_function", 0, props)
					if err != nil {
						warnEdge(b.logger, "CALL", f.Name, err)
						continue
					}
					b.insertCallEdge(ctx, f, callerNodeID, calleeNodeID, callNode.StartLine(), result)
					result.ExternalFuncs++
					continue
				}
				// Emit one CALL edge per same-name callee (each is a distinct
				// function node) so no definition is silently shadowed.
				for _, calleeID := range calleeIDs {
					calleeNodeID, err := b.store.GetOrCreateGraphNode(ctx, "function", calleeID, "")
					if err != nil {
						warnEdge(b.logger, "CALL", f.Name, err)
						continue
					}
					b.insertCallEdge(ctx, f, callerNodeID, calleeNodeID, callNode.StartLine(), result)
				}
			}
		}
	})
	return result, err
}

// insertCallEdge persists one CALL edge with call_line set to the call site
// line (previously it stamped the callee function's start line, a latent bug).
func (b *CallGraphBuilder) insertCallEdge(ctx context.Context, f *db.Function, callerNodeID, calleeNodeID int64, callLine int, result *BuildResult) {
	props := marshalProps(b.logger, "CALL", map[string]int{"call_line": callLine})
	_, err := b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      callerNodeID,
		DstID:      calleeNodeID,
		EdgeType:   "CALL",
		Properties: props,
	})
	if err != nil {
		warnEdge(b.logger, "CALL", f.Name, err)
		return
	}
	result.EdgesCreated++
}

func extractCallName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" || child.Kind() == "field_expression" {
			return child.Text()
		}
	}
	return ""
}
