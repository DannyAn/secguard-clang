package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// OwnershipTransferFilter drops memory-leak / resource-leak candidates whose
// variable is ownership-transferred out of the function (returned to the caller
// or stored to a global). It reads the OWNERSHIP_TRANSFER edges the graph layer
// persists (graph/ownership.go), closing the loop on those edges: they were
// built but never consumed by the convergence pipeline.
//
// This is a graph-native safety net on top of the detector's AST analysis (which
// emits the corresponding RELEASE events): any transfer the detector misses is
// still suppressed here, so a returned/stored pointer is never reported as a
// leak.
type OwnershipTransferFilter struct {
	store db.Store
}

func NewOwnershipTransferFilter(store db.Store) *OwnershipTransferFilter {
	return &OwnershipTransferFilter{store: store}
}

func (f *OwnershipTransferFilter) Name() string { return "ownership_transfer" }

func (f *OwnershipTransferFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	edges, err := f.store.ListGraphEdgesByType(ctx, "OWNERSHIP_TRANSFER")
	if err != nil {
		return nil, nil, fmt.Errorf("ownership transfer filter: %w", err)
	}
	if len(edges) == 0 {
		return candidates, nil, nil
	}

	// Resolve variable_ref nodes (edge source = the transferred variable) to
	// (function ID, name).
	nameByNode := make(map[int64]string)
	funcByNode := make(map[int64]int64)
	nodes, err := f.store.ListGraphNodesByEntityType(ctx, "variable_ref")
	if err != nil {
		return candidates, nil, nil // degrade: keep all
	}
	for _, n := range nodes {
		var props struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(n.Properties), &props) != nil || props.Name == "" {
			continue
		}
		nameByNode[n.ID] = props.Name
		funcByNode[n.ID] = n.EntityID
	}

	transferred := make(map[string]bool)
	for _, e := range edges {
		if name := nameByNode[e.SrcID]; name != "" {
			transferred[fmt.Sprintf("%d:%s", funcByNode[e.SrcID], name)] = true
		}
	}

	kept, dropped := partition(candidates,
		func(c Candidate) bool {
			return !transferred[fmt.Sprintf("%d:%s", c.FunctionID, c.VariableName)]
		},
		func(c Candidate) string {
			return fmt.Sprintf("variable %s is ownership-transferred (returned or stored to a global)", c.VariableName)
		},
		f.Name())
	return kept, dropped, nil
}
