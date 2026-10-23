package planner

import "testing"

// TestCandidateTypedViews pins the Phase-9 typed-view contract: Candidate's
// flat struct remains the single source of truth (so existing literals and
// JSON serialization are unchanged), and the typed views (Common / Leak /
// Free / Buffer / IntOverflow / Race / Divisor / Contract) expose a smaller,
// type-grouped read surface over the same data.
func TestCandidateTypedViews(t *testing.T) {
	c := Candidate{
		DerefEventID:   11,
		FunctionID:     22,
		FunctionName:   "target",
		VariableName:   "p",
		Line:           42,
		SuspicionLevel: "confirmed",
		// Leak
		DefiniteLeak:   true,
		LeakEscapeKind: "none",
		LeakFreeLines:  "10,20",
		// Free
		FirstFree:   10,
		SecondFree:  20,
		MayFree:     true,
		FirstCallee: "release_helper",
		// Buffer
		Array:        "buf",
		Index:        "i",
		Size:         16,
		CopySize:     "n",
		DstCapacity:  "16",
		SizeArgument: "sizeof(buf)",
		// IntOverflow
		LHSKind:          "param",
		RHSKind:          "const",
		SubLHSInfluenced: true,
		SubSink:          "call_arg",
		// Race
		ThreadFunctions: "t1,t2",
		ThreadInstances: 2,
		MutexA:          "m_a",
		MutexB:          "m_b",
		// Divisor
		DivisorInterval: "[0, +inf)",
		DivisorCallers:  "3 direct call sites",
		// Contract
		Subject:      "resp",
		CountField:   "resp->group_num",
		UseLine:      99,
		Missing:      "ptr-null",
		EvidenceKind: "self",
		GuardLine:    50,
	}

	common := c.Common()
	if common.FunctionName != "target" || common.VariableName != "p" || common.Line != 42 {
		t.Errorf("Common() identity fields wrong: %+v", common)
	}
	if common.SuspicionLevel != "confirmed" {
		t.Errorf("Common() SuspicionLevel = %q, want confirmed", common.SuspicionLevel)
	}

	leak := c.Leak()
	if !leak.DefiniteLeak || leak.LeakEscapeKind != "none" || leak.LeakFreeLines != "10,20" {
		t.Errorf("Leak() wrong: %+v", leak)
	}

	free := c.Free()
	if free.FirstFree != 10 || free.SecondFree != 20 || !free.MayFree || free.FirstCallee != "release_helper" {
		t.Errorf("Free() wrong: %+v", free)
	}

	buf := c.Buffer()
	if buf.Array != "buf" || buf.Index != "i" || buf.Size != 16 || buf.SizeArgument != "sizeof(buf)" {
		t.Errorf("Buffer() wrong: %+v", buf)
	}

	io := c.IntOverflow()
	if io.LHSKind != "param" || io.RHSKind != "const" || !io.SubLHSInfluenced || io.SubSink != "call_arg" {
		t.Errorf("IntOverflow() wrong: %+v", io)
	}

	race := c.Race()
	if race.ThreadFunctions != "t1,t2" || race.ThreadInstances != 2 || race.MutexA != "m_a" || race.MutexB != "m_b" {
		t.Errorf("Race() wrong: %+v", race)
	}

	div := c.Divisor()
	if div.DivisorInterval != "[0, +inf)" || div.DivisorCallers != "3 direct call sites" {
		t.Errorf("Divisor() wrong: %+v", div)
	}

	contract := c.Contract()
	if contract.Subject != "resp" || contract.CountField != "resp->group_num" || contract.UseLine != 99 || contract.EvidenceKind != "self" {
		t.Errorf("Contract() wrong: %+v", contract)
	}

	// Mutating a view must NOT affect the source Candidate (snapshot semantics).
	common.FunctionName = "mutated"
	leak.LeakEscapeKind = "mutated"
	if c.FunctionName == "mutated" || c.LeakEscapeKind == "mutated" {
		t.Error("typed views must be snapshots, not live references")
	}
}
