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
// The dismissal is tier-sensitive. A NON-PROVING origin tier (`opaque-origin`,
// `external-unknown`, `callback-entry`, `assumed-return`, an unguarded open
// caller-arg root) is a fail-open ASSUMPTION about a source the tree cannot see;
// an in-tree caller of the candidate function does NOT discharge it (the caller's
// own value may come from the same open entry), so those rows are dismissed even
// when the function has in-tree callers. Only the `caller-arg` tier — where the
// null source IS an in-tree call-site argument — is kept when the caller chain is
// concrete, because that call site is what the AI can judge. Machine-proven tiers
// (`cfg-proof`, `malloc-fail`) and a count-gated `array-buffer` stay for the AI.
type BoundaryFailOpenFilter struct {
	mode  string
	scope string
}

// NewBoundaryFailOpenFilter builds the fail-open pre-dismissal for BOTH scan
// scopes. A boundary scan uses boundaryMode ("off"/"external"/"all",
// ledgered as boundary_fail_open). A complete-program scan maps the precision
// tier (issue #253 P0-6): "balanced" behaves like "external", "strict" like
// "all", and the dismissals are ledgered as precision_fail_open so the two
// policies stay distinguishable in the report. "off" disables the layer.
func NewBoundaryFailOpenFilter(boundary bool, boundaryMode, precisionTier string) *BoundaryFailOpenFilter {
	if boundary {
		return &BoundaryFailOpenFilter{mode: boundaryMode, scope: "boundary"}
	}
	switch precisionTier {
	case "balanced":
		return &BoundaryFailOpenFilter{mode: "external", scope: "complete-program"}
	case "strict":
		return &BoundaryFailOpenFilter{mode: "all", scope: "complete-program"}
	default:
		return &BoundaryFailOpenFilter{mode: "off", scope: "complete-program"}
	}
}

func (f *BoundaryFailOpenFilter) Name() string {
	if f.scope == "complete-program" {
		return "precision_fail_open"
	}
	return "boundary_fail_open"
}

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
			Reason:       f.dismissReason(c),
		})
	}
	return kept, dropped, nil
}

func (f *BoundaryFailOpenFilter) dismissReason(c Candidate) string {
	if f.scope == "complete-program" {
		return fmt.Sprintf("complete-program precision tier: non-proving null origin %q with no concrete in-tree NULL witness (auto-dismissed; set [scan].precision_tier=\"off\" to judge it)", c.NullOriginTier)
	}
	return fmt.Sprintf("boundary scan: non-proving null origin %q with no concrete in-tree NULL witness (auto-dismissed; scan the worktree root or set [scan].boundary_auto_dismiss=\"off\" to judge it)", c.NullOriginTier)
}

func (f *BoundaryFailOpenFilter) keep(c Candidate) bool {
	switch c.NullOriginTier {
	case "opaque-origin", "external-unknown", "callback-entry", "assumed-return":
		// A fail-open ASSUMPTION, not evidence:
		//   - opaque-origin / external-unknown: the null source is an out-of-tree
		//     contract (an externally defined type's field value, an unproven
		//     external call), not a caller argument;
		//   - callback-entry: the value is bound at a registration site the tree
		//     cannot bind (a function pointer's ctx), including a forwarding
		//     chain rooted at such a registration;
		//   - assumed-return: an in-scan callee graded maybe-null only by the
		//     fail-open inter-procedural assumption.
		// Production triage: these tiers dominated the boundary candidate count
		// at ~0.2% precision. An in-tree caller of the CANDIDATE function does
		// not prove any of them non-null — the caller's own argument can flow
		// from the same external entry — so it must not rescue the row. A row
		// with a real caller-null witness was reclassified to caller-arg by
		// NullableSourceFilter; nothing with these tiers carries one.
		return false
	case "caller-arg":
		// The null source is an in-tree call-site argument. A zero-call-site
		// root ("the value flows from an unguarded external entry") is the same
		// fail-open assumption as opaque-origin, so it is dismissed. A
		// forwarding hop or a function with in-tree callers names concrete call
		// sites the AI can judge, so it stays; "all" mode also drops the
		// forwarding-hop rows (a project that accepts the boundary contract as
		// non-null). A literal-NULL witness ("caller X passes NULL") is a
		// concrete defect and stays.
		if c.ChainKind == "root" {
			return false
		}
		if len(c.CallChain) > 0 || len(c.Callers) > 0 {
			return true
		}
		if c.ChainKind == "hop" {
			return f.mode != "all"
		}
		return f.mode != "all" && hasCallerNullLiteralWitness(c)
	default:
		// cfg-proof / malloc-fail / array-buffer: machine-proven, or a structural
		// chain fact the AI must judge — never pre-dismiss.
		return true
	}
}

// hasCallerNullLiteralWitness reports whether the candidate carries a literal
// NULL call-site witness ("caller X passes NULL"). A forwarding hop is NOT a
// NULL witness — it passes the caller's own unguarded parameter on — and a
// fail-open root/registration detail is an assumption, so neither counts here.
func hasCallerNullLiteralWitness(c Candidate) bool {
	return strings.Contains(c.CallerNullDetail, "passes NULL")
}
