//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

func TestDF_DeallocSubscriptFP(t *testing.T) {
	store, p := setupDetector(t, "tc_df_dealloc_subscript_fp.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewDoubleFreeDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "DOUBLE_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	type props struct {
		Variable   string `json:"variable"`
		FirstFree  int    `json:"first_free"`
		SecondFree int    `json:"second_free"`
	}
	for _, ev := range events {
		var pr props
		json.Unmarshal([]byte(ev.Properties), &pr)
		loc, _ := store.GetLocationByID(ctx, ev.LocationID)
		line := 0
		if loc != nil {
			line = loc.Line
		}
		fmt.Printf("DOUBLE_FREE: variable=%s line=%d first=%d second=%d\n", pr.Variable, line, pr.FirstFree, pr.SecondFree)
	}

	for _, ev := range events {
		var pr props
		json.Unmarshal([]byte(ev.Properties), &pr)
		if pr.Variable != "p" {
			t.Errorf("FALSE POSITIVE: variable=%s flagged as double-free but buf[0] and buf[1] are distinct", pr.Variable)
		}
	}

	foundPositive := false
	for _, ev := range events {
		var pr props
		json.Unmarshal([]byte(ev.Properties), &pr)
		if pr.Variable == "p" {
			foundPositive = true
		}
	}
	if !foundPositive {
		t.Error("positive control (double-free of p) should be flagged")
	}
}
