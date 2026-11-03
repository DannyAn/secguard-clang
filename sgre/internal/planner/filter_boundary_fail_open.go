package planner

import (
	"context"
	"fmt"
	"strings"
)

// BoundaryFailOpenFilter pre-dismisses the boundary-scan null-deref flood: in a
// scan tree with no entry point, every zero-caller pointer parameter is seeded
// fail-open, so its null source is an external contract the tree cannot see.
// Those rows carry no in-tree caller/callee proof; the AI can only re-derive the
// same "external contract" judgment for each one. They are dropped here (and
// counted in the dismissed ledger as boundary_fail_open) instead of consuming an
// AI batch.
//
// The dismissal is tier-sensitive: a NON-PROVING origin tier (`opaque-origin`,
// `external-unknown`, `callback-entry`, `assumed-return`, an unguarded open
// caller-arg root) is a fail-open ASSUMPTION, not evidence, and is dismissed
// unless the candidate carries a concrete in-tree caller-null witness (a caller
// that passes NULL / forwards an open parameter, or an in-tree caller chain).
// Machine-proven tiers (`cfg-proof`, `malloc-fail`), a count-gated
// `array-buffer`, and a witnessed caller-arg stay for the AI.
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
			Reason:       fmt.Sprintf("boundary scan: non-proving null origin %q has no concrete in-tree caller-null witness (auto-dismissed; scan the worktree root or set [scan].boundary_auto_dismiss=\"off\" to judge it)", c.NullOriginTier),
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
	case "opaque-origin", "external-unknown", "callback-entry", "assumed-return":
		// A fail-open ASSUMPTION, not evidence:
		//   - opaque-origin / external-unknown: the null source is an out-of-tree
		//     contract (an external caller's argument, a field of an externally
		//     defined type, an unproven external call);
		//   - callback-entry: the function is registered via a function pointer
		//     (ADDR_TAKEN) with zero direct call sites, so the pipeline cannot
		//     bind the registrar's ctx argument — the parameter nullability is an
		//     external registration contract the tree cannot see;
		//   - assumed-return: an in-scan callee graded maybe-null only by the
		//     fail-open inter-procedural assumption.
		// Production triage: these tiers dominate the candidate count and are
		// almost always negated by the framework contract. A row that DOES have
		// concrete evidence (an actual caller-null witness) was reclassified to
		// caller-arg by NullableSourceFilter; keep it if a detail slipped through
		// with this tier.
		return hasConcreteCallerNullWitness(c)
	case "caller-arg":
		// A caller-arg candidate is only evidence when a caller-null witness
		// exists: a literal NULL argument ("caller X passes NULL"), a forwarding
		// hop ("caller X forwards Y from an unguarded entry chain"), or the
		// caller chain itself. An open chain rooted at a zero-call-site external
		// entry ("the value flows from an unguarded external entry") is the same
		// fail-open assumption as opaque-origin, so it is dismissed. "all" mode
		// also drops the forwarding-hop rows (a project that accepts the boundary
		// contract as non-null).
		if c.ChainKind == "root" || !hasConcreteCallerNullWitness(c) {
			return false
		}
		return f.mode != "all"
	default:
		// cfg-proof / malloc-fail / array-buffer: machine-proven, or a structural
		// chain fact the AI must judge — never pre-dismiss.
		return true
	}
}

// hasConcreteCallerNullWitness reports whether a candidate carries a real
// in-tree caller fact rather than a zero-call-site/registration-site
// assumption. A forwarding hop (ChainKind "hop") and a "caller <name> ..."
// detail both name an actual call site; the fail-open root detail ("the value
// flows from an unguarded external entry") and the callback registration detail
// ("function ... is registered via a function-pointer") do not.
func hasConcreteCallerNullWitness(c Candidate) bool {
	if c.ChainKind == "hop" {
		return true
	}
	return strings.HasPrefix(c.CallerNullDetail, "caller ")
}
