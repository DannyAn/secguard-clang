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

// TestUncheckedReturn_TypeofAndMultiAssignFP locks in three false-positive
// fixes for the unchecked-return detector:
//  1. typeof(expr) in declarations/casts (GCC extension) — tree-sitter-c
//     v0.24.2 does not support typeof, so the parser preprocesses it to void *.
//     Without preprocessing, the AST fragments and the call is detached from
//     its assignment, producing a false unchecked-return event.
//  2. Chained assignment `a = b = malloc()` — the detector must collect ALL
//     assignment targets and suppress if ANY of them is null-checked.
//  3. void/scalar function whose name contains "alloc" (e.g.
//     storage_spec_generator_log_allocate_size_init) — fail-closed: an
//     external function not in the index is not flagged.
//
// The positive control (unguarded malloc) must still be flagged.
func TestUncheckedReturn_TypeofAndMultiAssignFP(t *testing.T) {
	store, p := setupDetector(t, "tc_typeof_unchecked_return_fp.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewUncheckedReturnDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	type props struct {
		Function   string `json:"function"`
		Expression string `json:"expression"`
	}
	flagged := map[string]int{}
	for _, ev := range events {
		var pr props
		json.Unmarshal([]byte(ev.Properties), &pr)
		flagged[pr.Function]++
	}

	for _, fn := range []string{"xlog_malloc", "nlog_malloc"} {
		if flagged[fn] > 0 {
			t.Errorf("FALSE POSITIVE: %s should not be flagged (typeof/multi-assign case with null check)", fn)
		}
	}
	if flagged["storage_spec_generator_log_allocate_size_init"] > 0 {
		t.Error("FALSE POSITIVE: void function with alloc-like name should not be flagged")
	}
	if flagged["malloc"] != 1 {
		t.Errorf("positive control: expected exactly 1 unchecked malloc event, got %d", flagged["malloc"])
	}
}

// TestUncheckedReturn_TypeofAndMultiAssignFP_Planner verifies the full planner
// pipeline (detector → filter → candidates) does not surface confirmed
// candidates for the false-positive cases.
func TestUncheckedReturn_TypeofAndMultiAssignFP_Planner(t *testing.T) {
	store, p := setupDetector(t, "tc_typeof_unchecked_return_fp.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewUncheckedReturnDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "unchecked-return")
	if err != nil {
		t.Fatalf("plan unchecked-return: %v", err)
	}
	for _, c := range res.Candidates {
		fn := c.Target.Function
		if fn == "case1_struct_init_child_parser" ||
			fn == "case2_xlog_malloc_topn_data" ||
			fn == "case3_kafka_dns_fill" ||
			fn == "case5_set_thrt_comm" ||
			fn == "case4_storage_cap_attri_init" ||
			fn == "case6___typeof" ||
			fn == "case7___typeof__" ||
			fn == "case8_typeof_unqual" {
			t.Errorf("FALSE POSITIVE candidate: %s should not be flagged", fn)
		}
	}
}
