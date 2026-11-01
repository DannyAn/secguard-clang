package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// InlineSuppressionFilter is the in-source suppression front filter (GAP-11). It
// runs FIRST in every filter chain, before call-reach/safe-function and before
// any auto-confirm: a `// secguard-disable-next-line: <type>` comment is the
// user's explicit "never report this line" instruction and must win over every
// downstream judgment, including a machine-proved confirmed defect.
//
// It is a pure subtraction (drop the suppressed candidate, never re-tier), so
// it can introduce no false positive. The suppression set is loaded once per
// filter and keyed by (file, line); the type match ("all" wildcard or the exact
// type) is applied at load time.
type InlineSuppressionFilter struct {
	store    db.Store
	vulnType string
	loaded   bool
	byFile   map[int64]map[int]bool
}

func NewInlineSuppressionFilter(store db.Store, vulnType string) *InlineSuppressionFilter {
	return &InlineSuppressionFilter{store: store, vulnType: vulnType}
}

func (f *InlineSuppressionFilter) Name() string { return "inline_suppression" }

func (f *InlineSuppressionFilter) load(ctx context.Context) error {
	if f.loaded {
		return nil
	}
	sups, err := f.store.ListInlineSuppressions(ctx)
	if err != nil {
		return err
	}
	f.byFile = make(map[int64]map[int]bool, len(sups))
	for _, s := range sups {
		if s.VulnType != "all" && s.VulnType != f.vulnType {
			continue
		}
		if f.byFile[s.FileID] == nil {
			f.byFile[s.FileID] = make(map[int]bool)
		}
		f.byFile[s.FileID][s.Line] = true
	}
	f.loaded = true
	return nil
}

func (f *InlineSuppressionFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if err := f.load(ctx); err != nil {
		// A store read failure must not silently drop candidates; keep all and
		// let the caller surface the error elsewhere (this filter has no error
		// channel to the planner's audit ledger).
		return candidates, nil, nil
	}
	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		if f.byFile[c.FileID][c.Line] {
			dropped = dismiss(dropped, c, f.Name(), "in-source suppression (secguard-disable)")
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}
