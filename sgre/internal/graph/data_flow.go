package graph

import (
	"context"
	"fmt"

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

	err := forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		assigns := root.FindAll("assignment_expression")
		returns := root.FindAll("return_statement")

		for _, f := range funcs {
			b.detectPointerAssignments(ctx, f, nodesInRange(assigns, f.StartLine, f.EndLine), result)
			b.detectPointerReturns(ctx, f, nodesInRange(returns, f.StartLine, f.EndLine), result)
		}
	})
	return result, err
}

func (b *DataFlowBuilder) detectPointerAssignments(ctx context.Context, f *db.Function, assigns []parser.Node, result *BuildResult) {
	for _, assign := range assigns {
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		rhs := children[1]
		if lhs.Kind() != "identifier" {
			continue
		}
		// Only a variable-to-variable copy (`p = q`) is a DATA_FLOW edge. A call
		// result (`p = f()`) is NOT a variable copy: emitting an edge whose RHS
		// is the function name made the flow engine treat `p = f()` as `p = f`
		// (a copy from a non-existent variable), silently clearing p's null state.
		// Return-value flow is handled by the RETURN edges + null-flow engine.
		if rhs.Kind() != "identifier" {
			continue
		}
		rhsName := rhs.Text()

		lhsNodeID, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, lhs.Text(), assign.StartLine()))
		if err != nil {
			warnEdge(b.logger, "DATA_FLOW", f.Name, err)
			continue
		}
		rhsNodeID, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, rhsName, assign.StartLine()))
		if err != nil {
			warnEdge(b.logger, "DATA_FLOW", f.Name, err)
			continue
		}
		props := marshalProps(b.logger, "DATA_FLOW", map[string]string{"variable": lhs.Text()})
		_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
			SrcID:      rhsNodeID,
			DstID:      lhsNodeID,
			EdgeType:   "DATA_FLOW",
			Properties: props,
		})
		if err != nil {
			warnEdge(b.logger, "DATA_FLOW", f.Name, err)
			continue
		}
		result.EdgesCreated++
	}
}

func (b *DataFlowBuilder) detectPointerReturns(ctx context.Context, f *db.Function, returns []parser.Node, result *BuildResult) {
	for _, ret := range returns {
		for _, child := range ret.NamedChildren() {
			if child.Kind() == "identifier" {
				retNodeID, err := b.store.GetOrCreateGraphNode(ctx, "return_slot", f.ID, "")
				if err != nil {
					warnEdge(b.logger, "DATA_FLOW", f.Name, err)
					continue
				}
				varNodeID, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, child.Text(), ret.StartLine()))
				if err != nil {
					warnEdge(b.logger, "DATA_FLOW", f.Name, err)
					continue
				}
				props := marshalProps(b.logger, "DATA_FLOW", map[string]string{"variable": child.Text()})
				_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
					SrcID:      varNodeID,
					DstID:      retNodeID,
					EdgeType:   "DATA_FLOW",
					Properties: props,
				})
				if err != nil {
					warnEdge(b.logger, "DATA_FLOW", f.Name, err)
					continue
				}
				result.EdgesCreated++
			}
		}
	}
}


