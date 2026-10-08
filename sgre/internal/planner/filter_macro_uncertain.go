package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// MacroUncertainFilter converges null-deref candidates whose only evidence is a
// macro-context flow proof without a concrete null source line. Unknown macro
// semantics (accessor, iterator, guard) are exactly where the deterministic
// proof is least reliable, so they are dismissed before AI rather than spending
// the classifier budget on an unprovable contract.
type MacroUncertainFilter struct {
	store db.Store
	macro *macroContextDetector
}

func NewMacroUncertainFilter(store db.Store, macro *macroContextDetector) *MacroUncertainFilter {
	return &MacroUncertainFilter{store: store, macro: macro}
}

func (f *MacroUncertainFilter) Name() string { return "macro_uncertain" }

func (f *MacroUncertainFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	files := listFilesByID(ctx, f.store)
	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		file := files[c.FileID]
		if file != nil && f.macro != nil {
			c.MacroContext = f.macro.hasMacroContext(file.Path, c.Line)
		}
		if c.SuspicionLevel != "confirmed" && c.SourceLine == 0 && c.MacroContext {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("macro-context candidate has no concrete null source line"))
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}
