package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// valueUseOrigins returns variable -> set of VALUE_USE origins from the store.
func valueUseOrigins(t *testing.T, fixture string) map[string]map[string]bool {
	t.Helper()
	store := runIndexAndDetect(t, fixture)
	events, err := store.ListEventsByType(context.Background(), "VALUE_USE")
	if err != nil {
		t.Fatalf("list VALUE_USE: %v", err)
	}
	flagged := make(map[string]map[string]bool)
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "" {
			continue
		}
		if flagged[props.Variable] == nil {
			flagged[props.Variable] = make(map[string]bool)
		}
		flagged[props.Variable][props.Origin] = true
	}
	return flagged
}

// TestUninit_StructPartialInit guards the struct-partial-init scenarios: a
// member read after only SOME members were assigned/memset must be reported,
// while whole-struct zeroing (memset whole, designated/positional initializer)
// must not.
func TestUninit_StructPartialInit(t *testing.T) {
	flagged := valueUseOrigins(t, "tc118_struct_partial_uninit.c")

	// Direct field assignment: only cfg_bad.type was written, cfg_bad.flags is
	// indeterminate → report.
	if !flagged["cfg_bad"]["struct_partial_uninit"] {
		t.Errorf("cfg_bad.flags (unassigned member) must be flagged as struct_partial_uninit, got %v", flagged["cfg_bad"])
	}
	// h_good only reads the assigned member → no report.
	if len(flagged["cfg_good"]) > 0 {
		t.Errorf("cfg_good (only assigned member used) must not be flagged, got %v", flagged["cfg_good"])
	}
	// Whole-struct memset then read → no report.
	if len(flagged["cfg_wm"]) > 0 {
		t.Errorf("cfg_wm (whole memset) must not be flagged, got %v", flagged["cfg_wm"])
	}
	// Partial memset of one member, read another → report.
	if !flagged["cfg_pm"]["struct_partial_uninit"] {
		t.Errorf("cfg_pm.flags (only cfg_pm.type memset) must be flagged as struct_partial_uninit, got %v", flagged["cfg_pm"])
	}
	// Designated initializer zero-fills the rest per C11 6.7.9 p19/p21 → no report.
	if len(flagged["p_des"]) > 0 {
		t.Errorf("p_des (designated initializer zero-fills) must not be flagged, got %v", flagged["p_des"])
	}

	// Heap: completely-uninitialized field read → report.
	if !flagged["m_s1"]["heap_uninit"] {
		t.Errorf("m_s1->status (no init after malloc) must be flagged as heap_uninit, got %v", flagged["m_s1"])
	}
	// Heap: one member assigned, a different member read → report (field-sensitive).
	if !flagged["m_partial"]["heap_uninit"] {
		t.Errorf("m_partial->len (only m_partial->status assigned) must be flagged as heap_uninit, got %v", flagged["m_partial"])
	}
	// Heap: whole-block memset → no report.
	if len(flagged["m_good"]) > 0 {
		t.Errorf("m_good (whole memset after malloc) must not be flagged, got %v", flagged["m_good"])
	}
}
