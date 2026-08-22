package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// SharedAccessFilter confirms shared-data-race candidates against the persisted
// GLOBAL_ACCESS graph: a candidate is "confirmed" when two or more of its thread
// functions write (or read while another writes) the same global. It is fail-open
// (keeps the candidate when the graph is incomplete), and the detector has
// already done the precise lockset intersection, so this only upgrades confidence.
type SharedAccessFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewSharedAccessFilter(store db.Store, p *parser.Parser, logger *log.Logger) *SharedAccessFilter {
	return &SharedAccessFilter{store: store, parser: p, logger: logger}
}

func (f *SharedAccessFilter) Name() string { return "shared_access" }

func (f *SharedAccessFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	edges, err := f.store.ListGraphEdgesByType(ctx, "GLOBAL_ACCESS")
	if err != nil {
		return nil, nil, fmt.Errorf("shared access: %w", err)
	}
	if len(edges) == 0 {
		return candidates, nil, nil
	}

	nameByNode := make(map[int64]string)
	kindByNode := make(map[int64]string)
	if nodes, err := f.store.ListGraphNodesByEntityType(ctx, "function"); err == nil {
		for _, n := range nodes {
			var props struct {
				Name string `json:"name"`
			}
			if json.Unmarshal([]byte(n.Properties), &props) == nil && props.Name != "" {
				nameByNode[n.ID] = props.Name
			}
		}
	}
	if nodes, err := f.store.ListGraphNodesByEntityType(ctx, "global_var"); err == nil {
		for _, n := range nodes {
			var props struct {
				Name string `json:"name"`
			}
			if json.Unmarshal([]byte(n.Properties), &props) == nil && props.Name != "" {
				kindByNode[n.ID] = props.Name
			}
		}
	}

	// accessByFunc maps global -> map[function] -> access kind.
	accessByFunc := make(map[string]map[string]string)
	for _, e := range edges {
		fn, g := nameByNode[e.SrcID], kindByNode[e.DstID]
		if fn == "" || g == "" {
			continue
		}
		var props struct {
			Access string `json:"access"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if accessByFunc[g] == nil {
			accessByFunc[g] = make(map[string]string)
		}
		accessByFunc[g][fn] = props.Access
	}

	kept := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Category != "shared_data_race" {
			kept = append(kept, c)
			continue
		}
		event, err := f.store.GetEventByID(ctx, c.DerefEventID)
		if err != nil || event == nil {
			kept = append(kept, c)
			continue
		}
		p := parseEventProps(event.Properties)
		if p.Variable == "" || p.ThreadFunctions == "" {
			kept = append(kept, c)
			continue
		}
		// thread_functions is a comma list; a data race needs two functions with
		// at least one write on the same global.
		threads := strings.Split(p.ThreadFunctions, ",")
		accesses := accessByFunc[p.Variable]
		writers := 0
		readers := 0
		for _, t := range threads {
			t = strings.TrimSpace(t)
			if a := accesses[t]; a != "" {
				if strings.Contains(a, "write") {
					writers++
				} else {
					readers++
				}
			}
		}
		if writers >= 1 && writers+readers >= 2 {
			c.SuspicionLevel = "confirmed"
		}
		kept = append(kept, c)
	}
	return kept, nil, nil
}
