package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
)

type DataFlowFilter struct {
	store db.Store
}

func NewDataFlowFilter(store db.Store) *DataFlowFilter {
	return &DataFlowFilter{store: store}
}

func (f *DataFlowFilter) Name() string { return "data_flow" }

func (f *DataFlowFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	dataFlowEdges, err := f.store.ListGraphEdgesByType(ctx, "DATA_FLOW")
	if err != nil {
		return nil, err
	}
	if len(dataFlowEdges) == 0 {
		return candidates, nil
	}

	hasDataFlow := make(map[int64]bool)
	for _, edge := range dataFlowEdges {
		hasDataFlow[edge.SrcID] = true
		hasDataFlow[edge.DstID] = true
	}

	var result []Candidate
	for _, c := range candidates {
		c.HasDataFlow = true
		result = append(result, c)
	}
	return result, nil
}
