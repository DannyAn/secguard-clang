//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

func TestSwitchFlow_Detect(t *testing.T) {
	store, p := setupDetector(t, "tc172_switch_flow.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewSwitchFlowDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "SWITCH_FLOW")
	if err != nil {
		t.Fatalf("list SWITCH_FLOW: %v", err)
	}

	type got struct {
		Category string `json:"category"`
	}
	byFunc := map[string]map[string]bool{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props got
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if byFunc[fn.Name] == nil {
			byFunc[fn.Name] = map[string]bool{}
		}
		byFunc[fn.Name][props.Category] = true
	}

	if !byFunc["sf01_fallthrough"]["fallthrough"] {
		t.Errorf("sf01_fallthrough: expected fallthrough, got %v", byFunc["sf01_fallthrough"])
	}
	if !byFunc["sf02_fallthrough_call"]["fallthrough"] {
		t.Errorf("sf02_fallthrough_call: expected fallthrough, got %v", byFunc["sf02_fallthrough_call"])
	}
	if !byFunc["sf16_fallthrough_into_work"]["fallthrough"] {
		t.Errorf("sf16_fallthrough_into_work: expected fallthrough (shares next case's work), got %v", byFunc["sf16_fallthrough_into_work"])
	}
	if !byFunc["sf03_missing_default"]["missing_default"] {
		t.Errorf("sf03_missing_default: expected missing_default, got %v", byFunc["sf03_missing_default"])
	}
	for _, fn := range []string{"sf10_comment_exempt", "sf11_empty_case_chain", "sf12_int_switch_no_default", "sf14_compound_case", "sf15_fallthrough_into_return"} {
		if len(byFunc[fn]) > 0 {
			t.Errorf("%s: must NOT trigger, got %v", fn, byFunc[fn])
		}
	}
}

func TestSwitchFlow_UnhandledState(t *testing.T) {
	store, p := setupDetector(t, "tc173_switch_unhandled.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewSwitchFlowDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "SWITCH_FLOW")
	if err != nil {
		t.Fatalf("list SWITCH_FLOW: %v", err)
	}

	type got struct {
		Category  string `json:"category"`
		Reason    string `json:"reason"`
		StateVars string `json:"state_vars"`
		Default   string `json:"default"`
	}
	byFunc := map[string]got{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props got
		_ = json.Unmarshal([]byte(e.Properties), &props)
		byFunc[fn.Name] = props
	}

	wantReason := map[string]string{
		"fw01_state_machine_loop": "loop_progress",
		"fw02_parse_loop":         "loop_progress",
		"md03_result_unset":       "unhandled_state",
		"md04_empty_default":      "unhandled_state",
		"md05_error_code":         "unhandled_state",
	}
	for fn, reason := range wantReason {
		g := byFunc[fn]
		if g.Category != "missing_default" || g.Reason != reason {
			t.Errorf("%s: expected missing_default/%s, got %q/%q", fn, reason, g.Category, g.Reason)
		}
		if g.StateVars == "" {
			t.Errorf("%s: expected a state_vars value, got empty", fn)
		}
	}
	if g := byFunc["fw01_state_machine_loop"]; !strings.Contains(g.StateVars, "state") {
		t.Errorf("fw01_state_machine_loop: expected state in state_vars, got %q", g.StateVars)
	}
	if g := byFunc["fw02_parse_loop"]; !strings.Contains(g.StateVars, "pos") {
		t.Errorf("fw02_parse_loop: expected pos in state_vars, got %q", g.StateVars)
	}
	if g := byFunc["md04_empty_default"]; g.Default != "empty" {
		t.Errorf("md04_empty_default: expected default=empty, got %q", g.Default)
	}

	for _, fn := range []string{"md10_effective_default", "md11_full_enum_covered", "md12_no_downstream", "md13_loop_unrelated", "md14_int_switch_no_state"} {
		if g := byFunc[fn]; g.Category != "" {
			t.Errorf("%s: must NOT trigger, got %+v", fn, g)
		}
	}
}
