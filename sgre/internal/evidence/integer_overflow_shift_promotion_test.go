//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// Issue #214 shape 5: a narrow shift operand is promoted to 32-bit int before
// the shift, so `uint8_t x << 8` is legal. Judging the count against the
// DECLARED 8-bit width auto-confirmed every narrow widening as CWE-758.
func TestIntegerOverflow_ShiftUsesPromotedWidth(t *testing.T) {
	store, p := setupDetector(t, "tc182_shift_integer_promotion.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewIntegerOverflowDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "INTEGER_OVERFLOW")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	byFunction := make(map[string]string)
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct {
			Category string `json:"category"`
			Width    string `json:"shift_width"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		byFunction[fn.Name] = props.Category + "|" + props.Width
	}

	for _, fn := range []string{"shift_u8_widen", "shift_u16_widen", "shift_u64_ok"} {
		if got, ok := byFunction[fn]; ok {
			t.Errorf("%s: expected no shift-UB event (promoted width), got %s", fn, got)
		}
	}
	want := map[string]string{
		"shift_u8_ub32":  "shift_count_ub|32",
		"shift_u8_ub40":  "shift_count_ub|32",
		"shift_u32_ub32": "shift_count_ub|32",
	}
	for fn, wantCategory := range want {
		if got := byFunction[fn]; got != wantCategory {
			t.Errorf("%s: got %q, want %q", fn, got, wantCategory)
		}
	}
}
