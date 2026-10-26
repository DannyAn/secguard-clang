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
			c.MacroContext = f.macro.macroContextAt(ctx, f.store, c.FunctionID, file.Path, c.Line)
		}
		// A CFG proof assumes no macro rewrites the tracked variable, but the
		// CFG does not expand function-like macros: a list-iteration macro
		// (`SLL_Scan` & friends) assigns its iterator inside the loop header, so
		// "p = NULL with no intervening reassignment" is a FALSE proof there.
		// The pipeline already refuses to auto-confirm a macro-context candidate
		// (splitBySuspicion); demoting the level keeps the candidate FILE honest
		// instead of presenting the row as machine-proved and forcing the AI to
		// re-derive the contradiction.
		//
		// The demotion is gated on the macro actually naming the variable: a
		// macro that never receives it (`LIST_FOR_EACH(iter, head)` around a `q`
		// dereference) cannot have reassigned it, so that proof still stands.
		if c.MacroContext && c.SuspicionLevel == "confirmed" && file != nil && f.macro != nil &&
			f.macro.macroContextMentions(ctx, f.store, c.FunctionID, file.Path, c.Line, c.VariableName) {
			c.SuspicionLevel = "suspected"
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
