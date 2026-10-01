//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// TestDF_DeallocLoop_NoFP pins the original double-free false positive: a
// deallocator wrapper that iterates its pointer parameter (`free_item(&list[i])`)
// and takes an integer count. Two calls with the same count constant must not
// read as a double-free of that constant.
func TestDF_DeallocLoop_NoFP(t *testing.T) {
	store, p := setupDetector(t, "tc_df_dealloc_loop_fp.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewDoubleFreeDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "DOUBLE_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	var flagged []string
	for _, ev := range events {
		var pr struct {
			Variable string `json:"variable"`
		}
		json.Unmarshal([]byte(ev.Properties), &pr)
		flagged = append(flagged, pr.Variable)
	}

	for _, v := range flagged {
		if v != "p" {
			t.Errorf("FALSE POSITIVE: %q flagged as double-free (only the positive-control p should be flagged)", v)
		}
	}
	if len(flagged) == 0 {
		t.Error("positive control (double-free of p) should be flagged")
	}
}

// TestDF_TypedefPtrParam_Detected pins that a typedef-hidden pointer parameter
// (`typedef struct node *node_ptr_t`) is still treated as a pointer, so a real
// double-free through such a wrapper is not missed.
func TestDF_TypedefPtrParam_Detected(t *testing.T) {
	store, p := setupDetector(t, "tc_df_typedef_ptr_fp.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewDoubleFreeDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "DOUBLE_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	vars := map[string]bool{}
	for _, ev := range events {
		var pr struct {
			Variable string `json:"variable"`
		}
		json.Unmarshal([]byte(ev.Properties), &pr)
		vars[pr.Variable] = true
	}

	for _, want := range []string{"a", "p"} {
		if !vars[want] {
			t.Errorf("missing double-free of %q (typedef pointer double-free must stay flagged), got %v", want, vars)
		}
	}
}
