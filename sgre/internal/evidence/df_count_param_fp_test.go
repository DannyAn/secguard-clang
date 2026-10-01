//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// TestDF_CountParamFP pins that a deallocator wrapper whose body directly frees
// a scalar count/flag parameter (`free(max_num)`) does not mark that parameter
// as freed, so a caller passing the same constant to two calls is not read as a
// double-free of the count. Genuine pointer double-frees stay flagged.
func TestDF_CountParamFP(t *testing.T) {
	store, p := setupDetector(t, "tc_df_count_param_fp.c")
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

	for _, scalar := range []string{"LOGSEND_MAX_NUM", "4"} {
		if vars[scalar] {
			t.Errorf("FALSE POSITIVE: scalar count param %q flagged as double-free", scalar)
		}
	}
	for _, want := range []string{"p", "q", "buf"} {
		if !vars[want] {
			t.Errorf("missing double-free of %q (genuine pointer double-free must stay flagged), got %v", want, vars)
		}
	}
}
