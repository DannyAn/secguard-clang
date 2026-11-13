//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// Issue #253 P2-1: an explicit bounds guard before the access
// (`if (idx >= 16) continue;`, `if (idx < 16) { arr[idx] = ... }`) makes the
// loop-bound OOB proof unsound; the auto-confirmed `array_oob_write` category
// must not fire through it. A guard on another variable or with a bound larger
// than the capacity does NOT protect the access (control cases).
func TestBufferOverflowGuardBeforeArrayAccess(t *testing.T) {
	store, p := setupDetector(t, "zz_oob_guard.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewBufferOverflowDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}
	events, err := store.ListEventsByType(context.Background(), "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	oobByFunc := map[string]bool{}
	for _, e := range events {
		var props struct {
			Category string `json:"category"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		// Only the machine-confirmed OOB categories matter here; the
		// *_unchecked variants are suspected leads and may still fire.
		if props.Category != "array_oob_write" && props.Category != "array_oob_read" {
			continue
		}
		fn, ferr := store.GetFunctionByID(context.Background(), e.EntityID)
		if ferr != nil || fn == nil {
			continue
		}
		oobByFunc[fn.Name] = true
	}
	for _, fn := range []string{"guarded_continue", "guarded_return_loop", "guarded_body", "guarded_goto"} {
		if oobByFunc[fn] {
			t.Errorf("%s: a dominating bounds guard must suppress the auto-confirmed OOB", fn)
		}
	}
	for _, fn := range []string{"guarded_wrong_bound", "guarded_other_var", "unguarded"} {
		if !oobByFunc[fn] {
			t.Errorf("%s: the OOB proof must still fire (control)", fn)
		}
	}
}
