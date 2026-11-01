//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

func TestUnboundedLength_Detect(t *testing.T) {
	store, p := setupDetector(t, "tc178_unbounded_length.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewUnboundedLengthDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}
	events, err := store.ListEventsByType(context.Background(), "UNBOUNDED_LENGTH")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byFunc := map[string]bool{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props struct{ Category string `json:"category"` }
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Category == "unbounded_length" {
			byFunc[fn.Name] = true
		}
	}
	if !byFunc["ul01_recv_malloc"] {
		t.Errorf("ul01_recv_malloc: expected an unbounded_length event")
	}
	if byFunc["ul10_guarded"] {
		t.Errorf("ul10_guarded: upper-bound guard must exempt it")
	}
}
