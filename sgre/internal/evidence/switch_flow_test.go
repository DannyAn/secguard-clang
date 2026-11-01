//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
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
	if !byFunc["sf03_missing_default"]["missing_default"] {
		t.Errorf("sf03_missing_default: expected missing_default, got %v", byFunc["sf03_missing_default"])
	}
	for _, fn := range []string{"sf10_comment_exempt", "sf11_empty_case_chain", "sf12_int_switch_no_default"} {
		if len(byFunc[fn]) > 0 {
			t.Errorf("%s: must NOT trigger, got %v", fn, byFunc[fn])
		}
	}
}
