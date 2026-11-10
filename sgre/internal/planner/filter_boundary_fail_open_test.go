package planner

import (
	"context"
	"testing"
)

func boundaryCandidate(tier string) Candidate {
	return Candidate{FunctionName: "f", VariableName: "p", Line: 10, NullOriginTier: tier}
}

func TestBoundaryFailOpenFilterExternalMode(t *testing.T) {
	f := NewBoundaryFailOpenFilter(true, "external", "off")
	witness := boundaryCandidate("caller-arg")
	witness.CallerNullDetail = "caller caller_of_f passes NULL"
	kept, dropped, err := f.Apply(context.Background(), []Candidate{
		boundaryCandidate("opaque-origin"),
		boundaryCandidate("external-unknown"),
		boundaryCandidate("callback-entry"),
		witness,
		boundaryCandidate("assumed-return"),
		boundaryCandidate("array-buffer"),
		boundaryCandidate("cfg-proof"),
		boundaryCandidate("malloc-fail"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 4 || len(kept) != 4 {
		t.Fatalf("external mode kept=%d dropped=%d, want 4/4 (all non-proving tiers dismissed)", len(kept), len(dropped))
	}
	for _, d := range dropped {
		if d.Filter != "boundary_fail_open" || d.Reason == "" {
			t.Errorf("dropped entry lacks provenance: %+v", d)
		}
	}
}

// TestBoundaryFailOpenFilterDismissesNonProvingTiers pins the issue #200 policy:
// callback-entry and assumed-return are fail-open assumptions too and are
// pre-dismissed in the default mode, while a machine-proven tier survives.
func TestBoundaryFailOpenFilterDismissesNonProvingTiers(t *testing.T) {
	for _, mode := range []string{"external", "all"} {
		f := NewBoundaryFailOpenFilter(true, mode, "off")
		kept, dropped, err := f.Apply(context.Background(), []Candidate{
			boundaryCandidate("callback-entry"),
			boundaryCandidate("assumed-return"),
			boundaryCandidate("opaque-origin"),
			boundaryCandidate("external-unknown"),
			boundaryCandidate("malloc-fail"),
			boundaryCandidate("cfg-proof"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(dropped) != 4 || len(kept) != 2 {
			t.Errorf("%s mode: kept=%d dropped=%d, want 2/4 (non-proving dismissed, proven kept)", mode, len(kept), len(dropped))
		}
	}
}

// TestBoundaryFailOpenFilterKeepsWitness pins the escalation rule: a concrete
// in-tree caller-null witness overrides the tier policy. A forwarding hop
// (ChainKind "hop") and a literal-NULL caller argument are the evidence the
// issue asks to escalate on; a zero-call-site root and a callback registration
// contract are not.
func TestBoundaryFailOpenFilterKeepsWitness(t *testing.T) {
	hop := boundaryCandidate("caller-arg")
	hop.ChainKind = "hop"

	// A literal-NULL call site reclassifies the tier to caller-arg; it is the
	// one caller-null WITNESS (as opposed to a fail-open registration detail).
	named := boundaryCandidate("caller-arg")
	named.CallerNullDetail = "caller register_sender passes NULL"

	root := boundaryCandidate("caller-arg")
	root.ChainKind = "root"
	root.CallerNullDetail = "the value flows from an unguarded external entry (no in-tree call site guards this parameter)"

	callback := boundaryCandidate("callback-entry")
	callback.CallerNullDetail = "function send_ips is registered via a function-pointer (ADDR_TAKEN); parameter ips nullability is bound to the registration-site context — verify the registrar passes a non-null ctx"

	kept, dropped, err := NewBoundaryFailOpenFilter(true, "external", "off").Apply(context.Background(), []Candidate{hop, named, root, callback})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || len(dropped) != 2 {
		t.Fatalf("external mode witness split: kept=%d dropped=%d, want 2/2", len(kept), len(dropped))
	}
	if kept[0].ChainKind != "hop" || kept[1].CallerNullDetail != named.CallerNullDetail {
		t.Errorf("witness rows must be kept: %+v", kept)
	}
}

// TestBoundaryFailOpenFilterCallerArgRoot pins the "unguarded external entry"
// split: a caller-arg candidate rooted at an unguarded external entry (no
// concrete NULL witness) is the same fail-open assumption as opaque-origin, so
// it is dismissed in "external" mode; a forwarding hop keeps a concrete caller
// and stays for the AI unless "all" drops it.
func TestBoundaryFailOpenFilterCallerArgRoot(t *testing.T) {
	root := boundaryCandidate("caller-arg")
	root.ChainKind = "root"
	hop := boundaryCandidate("caller-arg")
	hop.ChainKind = "hop"

	kept, dropped, err := NewBoundaryFailOpenFilter(true, "external", "off").Apply(context.Background(), []Candidate{root, hop})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || len(kept) != 1 {
		t.Fatalf("external mode root/hop: kept=%d dropped=%d, want 1/1", len(kept), len(dropped))
	}
	if dropped[0].Reason == "" || kept[0].ChainKind != "hop" {
		t.Errorf("root must be dismissed, hop kept: dropped=%+v kept=%+v", dropped, kept)
	}
}

func TestBoundaryFailOpenFilterAllMode(t *testing.T) {
	f := NewBoundaryFailOpenFilter(true, "all", "off")
	hop := boundaryCandidate("caller-arg")
	hop.ChainKind = "hop"
	kept, dropped, err := f.Apply(context.Background(), []Candidate{
		hop,
		boundaryCandidate("assumed-return"),
		boundaryCandidate("array-buffer"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 2 || len(kept) != 1 {
		t.Fatalf("all mode kept=%d dropped=%d, want 1/2", len(kept), len(dropped))
	}
}

// TestBoundaryFailOpenFilterSourceTierVsInTreeCaller pins the source-tier rule
// (issue #215): an in-tree caller of the candidate function discharges only a
// caller-argument source. A non-proving SOURCE tier (opaque-origin /
// external-unknown / assumed-return) is an external contract the caller does not
// prove — the caller's own value can flow from the same open entry — so it stays
// dismissed even with an in-tree caller chain, in every mode.
func TestBoundaryFailOpenFilterSourceTierVsInTreeCaller(t *testing.T) {
	for _, mode := range []string{"external", "all"} {
		f := NewBoundaryFailOpenFilter(true, mode, "off")
		for _, tier := range []string{"opaque-origin", "external-unknown", "assumed-return"} {
			withCallers := boundaryCandidate(tier)
			withCallers.Callers = []string{"caller"}
			withChain := boundaryCandidate(tier)
			withChain.CallChain = []CallChainHop{{Caller: "caller", Callee: "f"}}

			kept, dropped, err := f.Apply(context.Background(), []Candidate{withCallers, withChain})
			if err != nil {
				t.Fatal(err)
			}
			if len(kept) != 0 || len(dropped) != 2 {
				t.Errorf("%s mode: %s with an in-tree caller must stay dismissed (an in-tree caller does not prove the source non-null): kept=%d dropped=%d",
					mode, tier, len(kept), len(dropped))
			}
		}

		// Control: the caller-argument source IS the in-tree caller's
		// argument, so the same caller chain keeps it judgeable.
		callerArg := boundaryCandidate("caller-arg")
		callerArg.Callers = []string{"caller"}
		kept, dropped, err := f.Apply(context.Background(), []Candidate{callerArg})
		if err != nil {
			t.Fatal(err)
		}
		if len(kept) != 1 || len(dropped) != 0 {
			t.Errorf("%s mode: caller-arg with an in-tree caller must be kept: kept=%d dropped=%d", mode, len(kept), len(dropped))
		}
	}
}

// TestPrecisionTierCompleteProgram pins issue #253 P0-6: a COMPLETE-PROGRAM
// scan pre-dismisses the same non-proving tiers under the "balanced" default,
// ledgered as precision_fail_open (distinct from the boundary ledger);
// "strict" additionally drops caller-arg forwarding hops, and "off" is the
// recall-maximal escape hatch.
func TestPrecisionTierCompleteProgram(t *testing.T) {
	hop := boundaryCandidate("caller-arg")
	hop.ChainKind = "hop"
	witness := boundaryCandidate("caller-arg")
	witness.CallerNullDetail = "caller entry passes NULL"
	proven := []Candidate{boundaryCandidate("cfg-proof"), boundaryCandidate("malloc-fail")}
	nonProving := []Candidate{
		boundaryCandidate("opaque-origin"),
		boundaryCandidate("external-unknown"),
		boundaryCandidate("callback-entry"),
		boundaryCandidate("assumed-return"),
	}

	balanced := NewBoundaryFailOpenFilter(false, "external", "balanced")
	kept, dropped, err := balanced.Apply(context.Background(), append(append([]Candidate{hop, witness}, nonProving...), proven...))
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 4 || len(kept) != 4 {
		t.Fatalf("balanced: kept=%d dropped=%d, want 4 kept (hop + witness + 2 proven) / 4 dropped", len(kept), len(dropped))
	}
	for _, d := range dropped {
		if d.Filter != "precision_fail_open" {
			t.Errorf("complete-program dismissals must be ledgered as precision_fail_open: %+v", d)
		}
	}

	strict := NewBoundaryFailOpenFilter(false, "external", "strict")
	kept, dropped, err = strict.Apply(context.Background(), append(append([]Candidate{hop, witness}, nonProving...), proven...))
	if err != nil {
		t.Fatal(err)
	}
	// strict drops the forwarding hop but a literal-NULL call-site witness is a
	// concrete defect and stays in EVERY mode (the documented policy).
	if len(dropped) != 5 || len(kept) != 3 {
		t.Fatalf("strict: kept=%d dropped=%d, want 3 kept (witness + 2 proven) / 5 dropped", len(kept), len(dropped))
	}
	foundWitness := false
	for _, c := range kept {
		if c.CallerNullDetail == witness.CallerNullDetail {
			foundWitness = true
		}
	}
	if !foundWitness {
		t.Error("strict must keep a caller-arg row with a literal-NULL witness")
	}

	off := NewBoundaryFailOpenFilter(false, "external", "off")
	kept, dropped, err = off.Apply(context.Background(), nonProving)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 0 || len(kept) != 4 {
		t.Fatalf("off: kept=%d dropped=%d, want everything kept", len(kept), len(dropped))
	}
}

func TestBoundaryFailOpenFilterOff(t *testing.T) {
	for _, f := range []*BoundaryFailOpenFilter{
		NewBoundaryFailOpenFilter(false, "external", "off"),
		NewBoundaryFailOpenFilter(true, "off", "off"),
	} {
		kept, dropped, err := f.Apply(context.Background(), []Candidate{
			boundaryCandidate("opaque-origin"),
			boundaryCandidate("external-unknown"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(dropped) != 0 || len(kept) != 2 {
			t.Fatalf("off must keep everything: kept=%d dropped=%d", len(kept), len(dropped))
		}
	}
}
