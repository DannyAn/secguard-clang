//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// TestStackEscape_Detect pins CWE-562 detection: the return shape (address of a
// non-static local / local array decay) is reported with return_stack_address;
// the store and async shapes are reported; the static/global/string/sync-helper
// shapes are NOT.
func TestStackEscape_Detect(t *testing.T) {
	store, p := setupDetector(t, "tc170_stack_escape.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewStackEscapeDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "STACK_ESCAPE")
	if err != nil {
		t.Fatalf("list STACK_ESCAPE: %v", err)
	}

	type got struct{ Category string }
	byFunc := map[string]map[string]bool{} // func -> category set
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

	for _, fn := range []string{"m1a_return_addr", "m1b_return_array", "m1c_return_elem_addr", "m1d_return_field_addr"} {
		if !byFunc[fn]["return_stack_address"] {
			t.Errorf("%s: expected return_stack_address, got %v", fn, byFunc[fn])
		}
	}
	if !byFunc["m2_store"]["escape_via_store"] {
		t.Errorf("m2_store: expected escape_via_store, got %v", byFunc["m2_store"])
	}
	if !byFunc["m3_async_arg"]["escape_via_async_arg"] {
		t.Errorf("m3_async_arg: expected escape_via_async_arg, got %v", byFunc["m3_async_arg"])
	}
	for _, fn := range []string{"fp_static_local", "fp_global", "fp_sync_helper", "fp_string", "fp_pointer_subscript"} {
		if len(byFunc[fn]) > 0 {
			t.Errorf("%s: must NOT trigger, got %v", fn, byFunc[fn])
		}
	}
}
