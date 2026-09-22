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

func TestUAF_DeallocIdFP(t *testing.T) {
	store, p := setupDetector(t, "tc_uaf_dealloc_id_fp.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewUseAfterFreeDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "USE_AFTER_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	type props struct {
		Variable string `json:"variable"`
	}
	for _, ev := range events {
		var pr props
		json.Unmarshal([]byte(ev.Properties), &pr)
		loc, _ := store.GetLocationByID(ctx, ev.LocationID)
		line := 0
		if loc != nil {
			line = loc.Line
		}
		fmt.Printf("USE_AFTER_FREE: variable=%s line=%d\n", pr.Variable, line)
	}

	for _, ev := range events {
		var pr props
		json.Unmarshal([]byte(ev.Properties), &pr)
		if pr.Variable == "BC_ORG_M_CACHE_ID" || pr.Variable == "BC_ORG_S_CACHE_ID" {
			t.Errorf("FALSE POSITIVE: %s (macro constant ID) flagged as use-after-free", pr.Variable)
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
		t.Error("positive control (use-after-free of p) should be flagged")
	}
}
