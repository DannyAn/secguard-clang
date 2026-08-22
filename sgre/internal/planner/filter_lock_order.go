package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// LockOrderFilter confirms deadlock candidates by finding a lock-order cycle in
// the persisted LOCK_ORDER graph. It upgrades a candidate to "confirmed" when its
// two mutexes are mutually reachable (a cycle), and otherwise keeps it as a
// suspicion (fail-open: an incomplete graph must never drop a detector finding).
type LockOrderFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewLockOrderFilter(store db.Store, p *parser.Parser, logger *log.Logger) *LockOrderFilter {
	return &LockOrderFilter{store: store, parser: p, logger: logger}
}

func (f *LockOrderFilter) Name() string { return "lock_order" }

func (f *LockOrderFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	edges, err := f.store.ListGraphEdgesByType(ctx, "LOCK_ORDER")
	if err != nil {
		return nil, nil, fmt.Errorf("lock order: %w", err)
	}
	if len(edges) == 0 {
		return candidates, nil, nil
	}

	nameByNode := make(map[int64]string)
	if nodes, err := f.store.ListGraphNodesByEntityType(ctx, "mutex"); err == nil {
		for _, n := range nodes {
			var props struct {
				Name string `json:"name"`
			}
			if json.Unmarshal([]byte(n.Properties), &props) == nil && props.Name != "" {
				nameByNode[n.ID] = props.Name
			}
		}
	}

	adj := make(map[string]map[string]bool)
	for _, e := range edges {
		from, to := nameByNode[e.SrcID], nameByNode[e.DstID]
		if from == "" || to == "" || from == to {
			continue
		}
		if adj[from] == nil {
			adj[from] = map[string]bool{}
		}
		adj[from][to] = true
	}

	kept := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		event, err := f.store.GetEventByID(ctx, c.DerefEventID)
		if err != nil || event == nil {
			kept = append(kept, c)
			continue
		}
		p := parseEventProps(event.Properties)
		if p.MutexA == "" || p.MutexB == "" {
			kept = append(kept, c)
			continue
		}
		if reachable(adj, p.MutexA, p.MutexB) && reachable(adj, p.MutexB, p.MutexA) {
			c.SuspicionLevel = "confirmed"
		}
		kept = append(kept, c)
	}
	return kept, nil, nil
}

// reachable reports whether to is reachable from from in adj.
func reachable(adj map[string]map[string]bool, from, to string) bool {
	if from == to {
		return true
	}
	visited := map[string]bool{from: true}
	stack := []string{from}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for m := range adj[n] {
			if m == to {
				return true
			}
			if !visited[m] {
				visited[m] = true
				stack = append(stack, m)
			}
		}
	}
	return false
}
