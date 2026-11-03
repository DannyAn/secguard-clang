package planner

import (
	"context"
	"fmt"
)

// UninitWeakTierFilter applies the issue #200 default-dismiss rule to the
// uninit type: the `init@unseen` tier is only a fail-open assumption ("no
// in-function write was found, but a cross-function factory/memset/output-param
// may have initialized the storage"), and production triage shows it dominates
// the candidate count with almost no real findings. A candidate is kept only
// when the detector attached the interprocedural conditional-uninit evidence:
// an in-tree callee writes the storage on some paths and its return is
// discarded (`(void)get(&x)`, a void writer that returns early on an error
// path). That is the shape where the read can actually see unwritten storage.
//
// The dismissal is ledgered, never silent: the dropped rows carry the
// uninit_weak_tier filter and the reason, so a recall review can inspect every
// row the policy removed.
type UninitWeakTierFilter struct{}

func NewUninitWeakTierFilter() *UninitWeakTierFilter { return &UninitWeakTierFilter{} }

func (f *UninitWeakTierFilter) Name() string { return "uninit_weak_tier" }

func (f *UninitWeakTierFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if len(candidates) == 0 {
		return candidates, nil, nil
	}
	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		if !weakUninitTier(c) {
			kept = append(kept, c)
			continue
		}
		dropped = dismiss(dropped, c, f.Name(),
			fmt.Sprintf("init@unseen: no in-tree callee error path leaves %s unwritten before the read at line %d (fail-open assumption; auto-dismissed)", c.VariableName, c.Line))
	}
	return kept, dropped, nil
}

// weakUninitTier reports whether c is the init@unseen tier with NO
// interprocedural evidence attached. InitWrite "cond" is the evidence tier (the
// detector found a conditional out-parameter writer). Stack/struct candidates
// are not weak-tier: their write-path state is tracked intra-procedurally, and
// the empty InitWrite on a struct/loop-read candidate is not the unseen claim.
func weakUninitTier(c Candidate) bool {
	if c.InitWrite != "none" {
		return false
	}
	return c.Origin == "heap_uninit" || c.Origin == "struct_partial_uninit"
}
