package planner

import (
	"context"
	"fmt"
)

// BoundaryFailOpenFilter pre-dismisses the boundary-scan null-deref flood: in a
// scan tree with no entry point, every zero-caller pointer parameter is seeded
// fail-open, so its null source is an external contract the tree cannot see.
// Those rows carry no in-tree caller/callee proof; the AI can only re-derive the
// same "external contract" judgment for each one. They are dropped here (and
// counted in the dismissed ledger as boundary_fail_open) instead of consuming an
// AI batch. A row with an in-tree caller chain, a machine-proven tier, or an
// array-buffer count field is left for the AI.
type BoundaryFailOpenFilter struct {
	mode string
}

func NewBoundaryFailOpenFilter(boundary bool, mode string) *BoundaryFailOpenFilter {
	if !boundary {
		mode = "off"
	}
	return &BoundaryFailOpenFilter{mode: mode}
}

func (f *BoundaryFailOpenFilter) Name() string { return "boundary_fail_open" }

func (f *BoundaryFailOpenFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.mode == "off" || len(candidates) == 0 {
		return candidates, nil, nil
	}
	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		if f.keep(c) {
			kept = append(kept, c)
			continue
		}
		dropped = append(dropped, Dismissed{
			FunctionName: c.FunctionName,
			VariableName: c.VariableName,
			Line:         c.Line,
			Filter:       f.Name(),
			Reason:       fmt.Sprintf("boundary scan: fail-open null origin %q has no in-tree caller/callee proof (auto-dismissed; scan the worktree root or set [scan].boundary_auto_dismiss=\"off\" to judge it)", c.NullOriginTier),
		})
	}
	return kept, dropped, nil
}

func (f *BoundaryFailOpenFilter) keep(c Candidate) bool {
	// An in-tree chain/caller is a concrete contract the AI can judge; never
	// pre-dismiss it. Only a pure zero-caller boundary symbol is a fail-open
	// external contract.
	if len(c.CallChain) > 0 || len(c.Callers) > 0 {
		return true
	}
	switch c.NullOriginTier {
	case "opaque-origin", "external-unknown":
		// No in-tree caller/callee proof: the null source is an out-of-tree
		// contract (an external caller's argument, a field of an externally
		// defined type, an unproven external call). Fail-open assumption, not
		// evidence — pre-dismiss it into the ledger.
		return false
	case "caller-arg", "assumed-return":
		// A caller-arg candidate whose open chain is rooted at an UNGUARDED
		// external entry (ChainKind "root", witness "the value flows from an
		// unguarded external entry") carries no concrete NULL witness — it is
		// the same fail-open assumption as opaque-origin, so it is dismissed
		// here too. A concrete caller ("caller X passes NULL") or a forwarding
		// hop ("caller X forwards Y") retains an in-tree caller detail the AI
		// can judge, so the default ("external") keeps it and only "all" drops
		// it. assumed-return never carries ChainKind, so it stays on the
		// default/"all" split unchanged.
		if c.ChainKind == "root" {
			return false
		}
		return f.mode != "all"
	default:
		// cfg-proof / malloc-fail / array-buffer / callback-entry. The first
		// three are machine-proven or need a chain judgment — never pre-dismiss.
		// callback-entry (ADDR_TAKEN, zero direct call sites) is DELIBERATELY
		// kept too: the function IS registered in-tree (that is what the
		// ADDR_TAKEN self-loop proves), but the graph does NOT record the
		// function-pointer invocation site, so the pipeline cannot prove the
		// registrar/invoker passes a non-null argument. A registrar that passes
		// NULL is a real defect, so dismissing it here would be a recall hole.
		// It stays suspected for the AI (and `off` mode surfaces it verbatim).
		return true
	}
}
