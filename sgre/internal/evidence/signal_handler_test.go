//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// TestSignalHandler_UnsafeCall pins CWE-479: a handler registered via signal(2)
// that directly calls malloc/printf is flagged, while a handler that only writes
// a volatile flag is not. This is the first end-to-end example of the
// ADDING_A_VULN_TYPE.md standard.
func TestSignalHandler_UnsafeCall(t *testing.T) {
	store, p := setupDetector(t, "tc108_signal_handler.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewSignalHandlerDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "SIGNAL_HANDLER")
	if err != nil {
		t.Fatalf("list SIGNAL_HANDLER: %v", err)
	}
	got := map[string]string{} // handler function -> unsafe callee
	for _, e := range events {
		var props struct {
			Function string `json:"function"`
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			got[props.Function] = props.Variable
		}
	}

	if got["watchdog_handler"] != "malloc" {
		t.Errorf("watchdog_handler should be flagged for malloc, got %v", got)
	}
	if got["logger_handler"] != "printf" {
		t.Errorf("logger_handler should be flagged for printf, got %v", got)
	}
	if _, ok := got["safe_handler"]; ok {
		t.Errorf("safe_handler (only a volatile write) must NOT be flagged, got %v", got)
	}
}
