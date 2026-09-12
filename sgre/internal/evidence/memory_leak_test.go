package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMemoryLeak_ConditionalLeak(t *testing.T) {
	store := runIndexAndDetect(t, "tc20_conditional_leak.c")
	assertHasEvent(t, store, "MEMORY_ALLOC", "ConditionalLeak")
}

func TestMemoryLeak_NoFreeAtAll(t *testing.T) {
	store := runIndexAndDetect(t, "tc05_memleak_no_free.c")
	assertHasEvent(t, store, "MEMORY_ALLOC", "NoFreeAtAll")
	assertNoEvent(t, store, "MEMORY_RELEASE", "NoFreeAtAll")
}

func TestMemoryLeak_OwnershipTransfer(t *testing.T) {
	store := runIndexAndDetect(t, "tc23_ownership_transfer.c")
	assertHasEvent(t, store, "MEMORY_RELEASE", "ownership_transfer")
}

func TestMemoryLeak_NullGuardNoLeak(t *testing.T) {
	store := runIndexAndDetect(t, "tc24_null_guard_no_leak.c")
	assertHasEvent(t, store, "MEMORY_RELEASE", "null_guard_no_leak")
}

// TestMemoryLeak_MallocInCondition locks in the `(var = malloc(n)) == NULL`
// short-circuit null-guard: the branch returns on failure and the success path
// frees, so it is released, not leaked — while a plain malloc-without-free is
// still reported.
func TestMemoryLeak_MallocInCondition(t *testing.T) {
	store := runIndexAndDetect(t, "tc52_malloc_in_condition.c")
	ctx := context.Background()

	released := make(map[string]bool)
	alloced := make(map[string]bool)

	allocEvents, err := store.ListEventsByType(ctx, "MEMORY_ALLOC")
	if err != nil {
		t.Fatalf("list MEMORY_ALLOC: %v", err)
	}
	for _, e := range allocEvents {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		alloced[props.Variable] = true
	}

	releaseEvents, err := store.ListEventsByType(ctx, "MEMORY_RELEASE")
	if err != nil {
		t.Fatalf("list MEMORY_RELEASE: %v", err)
	}
	for _, e := range releaseEvents {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		released[props.Variable] = true
	}

	if !released["path"] {
		t.Errorf("path (malloc-in-condition with free) should be released, released=%v alloced=%v", released, alloced)
	}
	if !alloced["buf"] || released["buf"] {
		t.Errorf("buf (genuine leak) should be alloced but not released, released=%v alloced=%v", released, alloced)
	}
}

// TestMemoryLeak_RAIICreateDestroy locks in the create/destroy RAII pairing: a
// create function whose destroy counterpart frees must not report its (stored-
// to-global-on-a-later-line) allocation as a leak. It guards the free-scan
// pre-pass in Detect (formerly per-candidate functionHasFrees os.ReadFile).
func TestMemoryLeak_RAIICreateDestroy(t *testing.T) {
	store := runIndexAndDetect(t, "tc74_raii_create_destroy.c")
	assertNoEvent(t, store, "MEMORY_ALLOC", "tc74_raii_create_destroy")
}

// TestMemoryLeak_ZcallocNotAlloc locks in the fix that only a real
// malloc/calloc/realloc call is an allocation: assigning an allocator function
// pointer (strm->zalloc = zcalloc, whose name contains "calloc") must not be
// reported as a leak.
func TestMemoryLeak_ZcallocNotAlloc(t *testing.T) {
	store := runIndexAndDetect(t, "tc53_zcalloc_not_alloc.c")
	ctx := context.Background()

	events, err := store.ListEventsByType(ctx, "MEMORY_ALLOC")
	if err != nil {
		t.Fatalf("list MEMORY_ALLOC: %v", err)
	}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "strm" {
			t.Errorf("strm (function-pointer assignment zalloc = zcalloc) must not be an allocation")
		}
	}
}

// TestMemoryLeak_FieldMallocEscape locks in the ownership-transfer of a malloc
// assigned directly to a field of a NON-LOCAL base (a parameter): it escapes
// into the caller-owned struct and is not a leak, while a malloc into a LOCAL
// struct's field still leaks.
func TestMemoryLeak_FieldMallocEscape(t *testing.T) {
	store := runIndexAndDetect(t, "tc54_field_malloc_escape.c")
	ctx := context.Background()

	leakVars := make(map[string]bool)
	releaseVars := make(map[string]bool)

	allocEvents, err := store.ListEventsByType(ctx, "MEMORY_ALLOC")
	if err != nil {
		t.Fatalf("list MEMORY_ALLOC: %v", err)
	}
	for _, e := range allocEvents {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		leakVars[props.Variable] = true
	}
	releaseEvents, err := store.ListEventsByType(ctx, "MEMORY_RELEASE")
	if err != nil {
		t.Fatalf("list MEMORY_RELEASE: %v", err)
	}
	for _, e := range releaseEvents {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		releaseVars[props.Variable] = true
	}

	// state (parameter struct field) escapes → it is released, not leaked.
	if !releaseVars["state"] {
		t.Errorf("state (field malloc into a parameter struct) should be released, not leaked; leakVars=%v releaseVars=%v", leakVars, releaseVars)
	}
	// local (local struct field, never freed) leaks → alloced without release.
	if !leakVars["local"] || releaseVars["local"] {
		t.Errorf("local (field malloc into a local struct, never freed) should leak (alloc without release); leakVars=%v releaseVars=%v", leakVars, releaseVars)
	}
}

// TestMemoryLeak_GuardedFreeNoLeak pins the guarded-release fix: a free inside a
// positive guard on the SAME pointer (`if (p) { free(p); }`) is a release, not a
// leak (the NULL path owns nothing), while a free guarded by an unrelated
// condition (`if (flag) { free(p); }`) still leaks.
func TestMemoryLeak_GuardedFreeNoLeak(t *testing.T) {
	store := runIndexAndDetect(t, "tc111_memory_leak_guarded_free.c")
	allocByFunc, releaseByFunc := countEventsByFunction(t, store, "MEMORY_ALLOC", "MEMORY_RELEASE")

	cases := []struct {
		fn     string
		allocs int
		rel    int
	}{
		{"guarded_free", 1, 1},
		{"conditional_free", 1, 0},
	}
	for _, c := range cases {
		if allocByFunc[c.fn] != c.allocs || releaseByFunc[c.fn] != c.rel {
			t.Errorf("%s: got %d alloc / %d release, want %d alloc / %d release",
				c.fn, allocByFunc[c.fn], releaseByFunc[c.fn], c.allocs, c.rel)
		}
	}
}

// TestMemoryLeak_OverwrittenPointer locks in the lost-allocation fix: a second
// write to the same variable overwrites the previous pointer, so
// `p = malloc(); p = malloc();` is TWO allocations and the first is lost even
// when the second is later freed (`... free(p)` must still report one leak).
func TestMemoryLeak_OverwrittenPointer(t *testing.T) {
	store := runIndexAndDetect(t, "tc110_memory_leak_overwrite.c")
	allocByFunc, releaseByFunc := countEventsByFunction(t, store, "MEMORY_ALLOC", "MEMORY_RELEASE")

	cases := []struct {
		fn     string
		allocs int
		rel    int
	}{
		{"overwrite_no_free", 2, 0},
		{"overwrite_then_free", 2, 1},
		{"overwrite_with_null", 1, 0},
		{"single_no_free", 1, 0},
		{"decl_then_assign", 1, 0},
	}
	for _, c := range cases {
		if allocByFunc[c.fn] != c.allocs || releaseByFunc[c.fn] != c.rel {
			t.Errorf("%s: got %d alloc / %d release, want %d alloc / %d release",
				c.fn, allocByFunc[c.fn], releaseByFunc[c.fn], c.allocs, c.rel)
		}
	}
}
