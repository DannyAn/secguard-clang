//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

func TestLoopBound_Detect(t *testing.T) {
	store, p := setupDetector(t, "tc180_loop_bound.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewLoopBoundDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}
	events, err := store.ListEventsByType(context.Background(), "LOOP_BOUND")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byFunc := map[string]string{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Category != "" {
			byFunc[fn.Name] = props.Category
		}
	}

	if got := byFunc["lb01_param_bound"]; got != "unchecked_input_bound" {
		t.Errorf("lb01_param_bound: expected unchecked_input_bound, got %q", got)
	}
	if got := byFunc["lb02_recv_bound"]; got != "unchecked_input_bound" {
		t.Errorf("lb02_recv_bound: expected unchecked_input_bound, got %q", got)
	}
	if got := byFunc["lb03_mul_bound"]; got != "bound_mul" {
		t.Errorf("lb03_mul_bound: expected bound_mul, got %q", got)
	}

	for _, neg := range []string{
		"lb10_const_bound", "lb11_guarded", "lb12_clamped", "lb13_while1",
		"lb14_descending", "lb15_local_bound", "lb16_traversal",
	} {
		if byFunc[neg] != "" {
			t.Errorf("%s: expected no LOOP_BOUND event, got %q", neg, byFunc[neg])
		}
	}
}
