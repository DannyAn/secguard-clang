package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// TestResourceLeak_DatablockNotResource locks in the "lock"-substring fix: a
// memory allocator named allocate_new_datablock (which contains "lock" inside
// "datablock") must not be treated as a lock/resource acquirer, and the base
// variable of a field write (ll->first = ...) must not be reported as a leaked
// resource.
func TestResourceLeak_DatablockNotResource(t *testing.T) {
	store := runIndexAndDetect(t, "tc49_datablock_not_resource.c")
	assertNoEvent(t, store, "RESOURCE_ACQUIRE", "tc49_datablock_not_resource")
}

// TestResourceLeak_ErrorCodeNotResource locks in the error-code fix: an
// "Open"-named call that returns an error code (compared against UNZ_OK) must
// not be flagged, while a genuine fopen leak must still be.
func TestResourceLeak_ErrorCodeNotResource(t *testing.T) {
	store := runIndexAndDetect(t, "tc51_open_error_code.c")
	events, _ := store.ListEventsByType(context.Background(), "RESOURCE_ACQUIRE")

	flagged := make(map[string]bool)
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Variable] = true
	}
	if flagged["err"] {
		t.Errorf("err (error code compared against UNZ_OK) must not be flagged as a resource, got %v", flagged)
	}
	if !flagged["f"] {
		t.Errorf("f (genuine fopen leak) should still be flagged, got %v", flagged)
	}
}
