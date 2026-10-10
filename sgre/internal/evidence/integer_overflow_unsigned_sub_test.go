//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

func TestIntegerOverflow_UnsignedSubUnderflow(t *testing.T) {
	store, p := setupDetector(t, "tc100_unsigned_sub_underflow.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewIntegerOverflowDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "INTEGER_OVERFLOW")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	type eventInfo struct {
		category string
	}
	byFunction := make(map[string][]eventInfo)
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		byFunction[fn.Name] = append(byFunction[fn.Name], eventInfo{category: props.Category})
	}

	for _, fn := range []string{"unsigned_sub_param", "unsigned_sub_subscript"} {
		found := false
		for _, e := range byFunction[fn] {
			if e.category == "unsigned_sub_underflow" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected unsigned_sub_underflow, got %v", fn, byFunction[fn])
		}
	}

	for _, fn := range []string{"unsigned_sub_guarded", "signed_sub", "unsigned_sub_constant", "unsigned_sub_same"} {
		if len(byFunction[fn]) != 0 {
			t.Errorf("%s: expected no integer-overflow event, got %v", fn, byFunction[fn])
		}
	}
}

// TestIntegerOverflow_UnsignedSubSnprintfAccumulator pins the P1-2 false-positive
// suppression: `size - count` where count is accumulated ONLY by a truncating
// snprintf wrapper (`count += snprintf_truncated_s(...)`) cannot underflow, so it
// must NOT emit unsigned_sub_underflow. A plain unsigned subtraction (the control)
// must still be flagged.
func TestIntegerOverflow_UnsignedSubSnprintfAccumulator(t *testing.T) {
	store, p := setupDetector(t, "tc128_int_overflow_snprintf_accumulator.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewIntegerOverflowDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "INTEGER_OVERFLOW")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	byFunction := make(map[string][]string)
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		byFunction[fn.Name] = append(byFunction[fn.Name], props.Category)
	}

	for _, cat := range byFunction["fmt_buf"] {
		if cat == "unsigned_sub_underflow" {
			t.Errorf("fmt_buf: size - count with a truncating-snprintf accumulator must not be flagged, got %v", byFunction["fmt_buf"])
		}
	}
	found := false
	for _, cat := range byFunction["bad_sub"] {
		if cat == "unsigned_sub_underflow" {
			found = true
		}
	}
	if !found {
		t.Errorf("bad_sub: plain unsigned subtraction must still be flagged, got %v", byFunction["bad_sub"])
	}
}
