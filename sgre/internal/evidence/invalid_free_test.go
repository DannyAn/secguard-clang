//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

func TestInvalidFree_Detect(t *testing.T) {
	store, p := setupDetector(t, "tc171_invalid_free.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewInvalidFreeDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "INVALID_FREE")
	if err != nil {
		t.Fatalf("list INVALID_FREE: %v", err)
	}

	type got struct {
		Category    string `json:"category"`
		PointeeKind string `json:"pointee_kind"`
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

	want := map[string]got{
		"f1_stack_array":   {"free_stack_object", "stack"},
		"f1b_addr_local":   {"free_stack_object", "stack"},
		"f2_mid_array":     {"free_offset_pointer", "stack"},
		"f3_global_array":  {"free_global_array", "global-array"},
		"f4_heap_offset":   {"free_offset_pointer", "heap-offset"},
		"f5_realloc_stack": {"free_stack_object", "stack"},
	}
	for fn, w := range want {
		g, ok := byFunc[fn]
		if !ok {
			t.Errorf("%s: expected an INVALID_FREE event, got none", fn)
			continue
		}
		if g.Category != w.Category || g.PointeeKind != w.PointeeKind {
			t.Errorf("%s: got (%s,%s), want (%s,%s)", fn, g.Category, g.PointeeKind, w.Category, w.PointeeKind)
		}
	}
	for _, fn := range []string{"fp1_free_ptr_var", "fp2_free_null"} {
		if _, ok := byFunc[fn]; ok {
			t.Errorf("%s: must NOT trigger, got %+v", fn, byFunc[fn])
		}
	}
}
