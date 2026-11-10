//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// containerFieldEvents returns the props of every MEMORY_ALLOC event emitted by
// the global-container shallow-free pass (origin=container_field).
func containerFieldEvents(t *testing.T, store db.Store) []map[string]string {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "MEMORY_ALLOC")
	if err != nil {
		t.Fatalf("list MEMORY_ALLOC: %v", err)
	}
	var out []map[string]string
	for _, e := range events {
		var props map[string]string
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		if props["origin"] == "container_field" {
			out = append(out, props)
		}
	}
	return out
}

// containerTransferReleases returns the alloc_line values of the ownership-
// transfer releases the pass emits for a heap argument handed into an escaping
// wrapper object.
func containerTransferReleases(t *testing.T, store db.Store) []int {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "MEMORY_RELEASE")
	if err != nil {
		t.Fatalf("list MEMORY_RELEASE: %v", err)
	}
	var out []int
	for _, e := range events {
		var props struct {
			Origin    string `json:"origin"`
			AllocLine int    `json:"alloc_line"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		if props.Origin == "container_transfer" {
			out = append(out, props.AllocLine)
		}
	}
	return out
}

// TestGlobalContainerFieldLeak_ShallowFree is the issue #255 repro: the inner
// cfg allocation is reachable only through g_policy_table[idx] -> policy ->
// policy->cfg, and policy_delete frees the outer object but not the field.
// The pass must report the field at the delete path with the full chain, and
// must re-home the create-site allocation (ownership transferred into the
// wrapper object) instead of reporting it as a definite leak.
func TestGlobalContainerFieldLeak_ShallowFree(t *testing.T) {
	store := runIndexAndDetect(t, "tc183_global_container_field_leak.c")

	events := containerFieldEvents(t, store)
	if len(events) != 1 {
		t.Fatalf("expected exactly one container-field leak event, got %d: %v", len(events), events)
	}
	props := events[0]
	if props["variable"] != "cfg" {
		t.Errorf("leaked field variable = %q, want cfg", props["variable"])
	}
	if props["container"] != "g_policy_table" {
		t.Errorf("container = %q, want g_policy_table", props["container"])
	}
	if props["slot"] != "g_policy_table[idx]" {
		t.Errorf("slot = %q, want g_policy_table[idx]", props["slot"])
	}
	if props["field"] != "cfg" {
		t.Errorf("field = %q, want cfg", props["field"])
	}
	wantChain := "g_policy_table[idx] -> policy -> policy->cfg"
	if props["ref_chain"] != wantChain {
		t.Errorf("ref_chain = %q, want %q", props["ref_chain"], wantChain)
	}
	if !strings.HasPrefix(props["shallow_free"], "policy_free:") {
		t.Errorf("shallow_free = %q, want policy_free:<line>", props["shallow_free"])
	}
	if !strings.HasPrefix(props["field_alloc"], "policy_create:") {
		t.Errorf("field_alloc = %q, want policy_create:<line>", props["field_alloc"])
	}
	if !strings.HasPrefix(props["field_store"], "policy_new:") {
		t.Errorf("field_store = %q, want policy_new:<line>", props["field_store"])
	}

	// The create-site candidate must be re-homed, not left as a definite leak
	// at the allocation line.
	released := containerTransferReleases(t, store)
	found := false
	for _, line := range released {
		if line > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("no container-transfer release for the cfg allocation; the create-site candidate stays a false positive")
	}
}

// TestGlobalContainerFieldLeak_DeepFree: freeing the field before the outer
// object is not a leak.
func TestGlobalContainerFieldLeak_DeepFree(t *testing.T) {
	store := runIndexAndDetect(t, "tc184_global_container_field_deep_free.c")
	if events := containerFieldEvents(t, store); len(events) != 0 {
		t.Errorf("deep free must not report a container-field leak, got %v", events)
	}
}

// TestGlobalContainerFieldLeak_NoSlotClear: a shallow release without clearing
// the slot leaves the field reachable through the (dangling) global pointer, so
// it is not a leak-by-loss; the pass must not report it.
func TestGlobalContainerFieldLeak_NoSlotClear(t *testing.T) {
	store := runIndexAndDetect(t, "tc185_global_container_field_no_clear.c")
	if events := containerFieldEvents(t, store); len(events) != 0 {
		t.Errorf("a release without a slot clear must not report a container-field leak, got %v", events)
	}
}

// TestGlobalContainerFieldLeak_ArrayContainer covers the array-of-pointers
// container form and a slot released/freed in place (`free(g_items[i])`).
func TestGlobalContainerFieldLeak_ArrayContainer(t *testing.T) {
	store := runIndexAndDetect(t, "tc187_global_container_array_shallow_free.c")
	events := containerFieldEvents(t, store)
	if len(events) != 1 {
		t.Fatalf("expected exactly one container-field leak event, got %d: %v", len(events), events)
	}
	if events[0]["container"] != "g_items" || events[0]["field"] != "name" {
		t.Errorf("unexpected container/field: %v", events[0])
	}
	if got := events[0]["slot"]; got != "g_items[slot]" {
		t.Errorf("slot = %q, want g_items[slot]", got)
	}
}

// TestGlobalContainerFieldLeak_ParamFillWrapper covers the "init helper fills a
// caller-owned object" shape: the wrapper stores a heap parameter into a field
// of an object it does not return.
func TestGlobalContainerFieldLeak_ParamFillWrapper(t *testing.T) {
	store := runIndexAndDetect(t, "tc188_global_container_param_fill.c")
	events := containerFieldEvents(t, store)
	if len(events) != 1 {
		t.Fatalf("expected exactly one container-field leak event, got %d: %v", len(events), events)
	}
	if !strings.HasPrefix(events[0]["field_store"], "policy_init:") {
		t.Errorf("field_store = %q, want policy_init:<line>", events[0]["field_store"])
	}
}

// TestGlobalContainerFieldLeak_DeepHelper: a release helper that frees the
// object's fields (proven by the parameter-field-free summary) is a deep
// release, not a shallow one.
func TestGlobalContainerFieldLeak_DeepHelper(t *testing.T) {
	store := runIndexAndDetect(t, "tc189_global_container_deep_helper.c")
	if events := containerFieldEvents(t, store); len(events) != 0 {
		t.Errorf("a deep release helper must not report a container-field leak, got %v", events)
	}
}

// TestGlobalContainerFieldLeak_BorrowedField: a pointer field assigned a
// non-heap value (a global string) has no heap witness and must not be
// reported even when the outer object is shallow-freed and the slot cleared.
func TestGlobalContainerFieldLeak_BorrowedField(t *testing.T) {
	store := runIndexAndDetect(t, "tc190_global_container_borrowed_field.c")
	if events := containerFieldEvents(t, store); len(events) != 0 {
		t.Errorf("a borrowed field value must not be reported, got %v", events)
	}
}

// TestGlobalContainerFieldLeak_WrapperReturnNotSuppressed is the recall guard
// for the re-homing rule: a wrapper object RETURNED to the caller (not stored
// into a global container) is a plain local ownership transfer. The pass must
// not emit a container-transfer release for the field's allocation, because no
// deletion-path analysis would then watch it — the create-site leak report must
// survive.
func TestGlobalContainerFieldLeak_WrapperReturnNotSuppressed(t *testing.T) {
	store := runIndexAndDetect(t, "tc191_global_container_wrapper_return_leak.c")
	if events := containerFieldEvents(t, store); len(events) != 0 {
		t.Errorf("a returned wrapper object is not a container slot; no container-field leak expected, got %v", events)
	}
	if !hasLeakEvent(t, store, "cfg") {
		t.Errorf("the cfg allocation must stay reported at the create site (no container ownership transfer)")
	}
}
