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
// It also back-fills the candidate's ReverseFunc from the reversed edge's
// function property so the reverse_order evidence fragment renders.
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

	// Batch-load every candidate's event once: the per-candidate GetEventByID
	// below was an N+1 query storm.
	eventIDs := make([]int64, 0, len(candidates))
	seen := make(map[int64]bool, len(candidates))
	for _, c := range candidates {
		if !seen[c.DerefEventID] {
			seen[c.DerefEventID] = true
			eventIDs = append(eventIDs, c.DerefEventID)
		}
	}
	eventsByID, err := f.store.ListEventsByIDs(ctx, eventIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("lock order: load events: %w", err)
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
	edgeFns := make(map[string]map[string]bool)
	for _, e := range edges {
		from, to := nameByNode[e.SrcID], nameByNode[e.DstID]
		if from == "" || to == "" || from == to {
			continue
		}
		if adj[from] == nil {
			adj[from] = map[string]bool{}
		}
		adj[from][to] = true
		if fn := edgeHolder(e.Properties); fn != "" {
			key := from + "\x00" + to
			if edgeFns[key] == nil {
				edgeFns[key] = map[string]bool{}
			}
			edgeFns[key][fn] = true
		}
	}

	kept := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		event := eventsByID[c.DerefEventID]
		if event == nil {
			kept = append(kept, c)
			continue
		}
		p := parseEventProps(event.Properties)
		if p.MutexA == "" || p.MutexB == "" {
			kept = append(kept, c)
			continue
		}
		// The reversed edge's holder is the OTHER site of the inversion —
		// without it the AI sees "locks A then B" but never learns who locks
		// them the other way around, so the reverse_order fragment and the
		// reverse@ hint never rendered before this back-fill.
		if c.ReverseFunc == "" {
			c.ReverseFunc = reverseHolder(edgeFns, p.MutexB, p.MutexA, c.FunctionName)
		}
		if p.Timed == "true" {
			// The cycle needed a pthread_mutex_timedlock acquisition, which
			// returns ETIMEDOUT, so the inversion is recoverable: report it
			// suspected and never upgrade it to confirmed.
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

// edgeHolder returns the acquiring function recorded in a LOCK_ORDER edge's
// properties.
func edgeHolder(props string) string {
	var ep struct {
		Function string `json:"function"`
	}
	if json.Unmarshal([]byte(props), &ep) == nil {
		return ep.Function
	}
	return ""
}

// reverseHolder picks a function that acquires the reversed pair (from→to),
// preferring one other than the candidate's own function: the AI needs the
// OTHER site of the inversion to confirm the deadlock.
func reverseHolder(edgeFns map[string]map[string]bool, from, to, self string) string {
	fns := edgeFns[from+"\x00"+to]
	first := ""
	for fn := range fns {
		if fn != self {
			return fn
		}
		if first == "" {
			first = fn
		}
	}
	return first
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
