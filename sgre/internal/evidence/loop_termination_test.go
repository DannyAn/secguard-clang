//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestLoopTermination_Detect(t *testing.T) {
	store, p := setupDetector(t, "tc180_loop_termination.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewLoopTerminationDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "LOOP_TERMINATION")
	if err != nil {
		t.Fatalf("list LOOP_TERMINATION: %v", err)
	}

	type got struct {
		Category string `json:"category"`
		Variable string `json:"variable"`
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

	positives := map[string]string{
		"lt01_no_progress_while":    "no_progress",
		"lt02_no_progress_for":      "no_progress",
		"lt03_zero_step":            "zero_step",
		"lt04_continue_bypass":      "continue_bypass",
		"lt05_protocol_offset":      "no_progress",
		"lt06_do_while_no_progress": "no_progress",
	}
	for fn, want := range positives {
		g := byFunc[fn]
		if g.Category != want {
			t.Errorf("%s: expected category %q, got %q (props %+v)", fn, want, g.Category, g)
		}
	}
	if byFunc["lt01_no_progress_while"].Variable != "i" {
		t.Errorf("lt01: expected progress variable i, got %q", byFunc["lt01_no_progress_while"].Variable)
	}

	negatives := []string{
		"lt20_normal_inc", "lt21_normal_dec", "lt22_while_true", "lt23_for_infinite",
		"lt24_break_exit", "lt25_return_exit", "lt26_external_update",
		"lt27_global_cond", "lt28_valid_parse", "lt29_addr_taken",
	}
	for _, fn := range negatives {
		if _, ok := byFunc[fn]; ok {
			t.Errorf("%s: must NOT trigger, got %+v", fn, byFunc[fn])
		}
	}
}

func TestLoopTermination_Planner(t *testing.T) {
	ctx := context.Background()
	store, p := setupDetector(t, "tc180_loop_termination.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewLoopTerminationDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "loop-termination")
	if err != nil {
		t.Fatalf("plan loop-termination: %v", err)
	}

	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		suspicion[c.Target.Function] = c.SuspicionLevel
	}

	for _, fn := range []string{"lt01_no_progress_while", "lt03_zero_step", "lt04_continue_bypass"} {
		if suspicion[fn] != "suspected" {
			t.Errorf("%s: expected suspected, got %q", fn, suspicion[fn])
		}
	}
	for _, fn := range []string{"lt20_normal_inc", "lt22_while_true", "lt24_break_exit", "lt27_global_cond"} {
		if _, present := suspicion[fn]; present {
			t.Errorf("%s: must NOT produce a candidate, got %q", fn, suspicion[fn])
		}
	}
}
