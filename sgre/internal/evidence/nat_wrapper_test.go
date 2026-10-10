package evidence

import "testing"

// TestMemoryLeak_NatFreeRecognized pins the zero-config deallocator heuristic:
// nat_free (which wraps the external VOS_FREE) must be recognized as a free, so
// `malloc + nat_free` is a release pair, not a leak.
func TestMemoryLeak_NatFreeRecognized(t *testing.T) {
	store := runIndexAndDetect(t, "tc_nat_alloc_free.c")
	assertHasEvent(t, store, "MEMORY_RELEASE", "tc_nat_alloc_free")
}

// TestMemoryLeak_NatMallocRecognized pins the zero-config allocator heuristic:
// nat_malloc (which wraps the external VOS_MALLOC) must be recognized as an
// allocation, so an unfreed nat_malloc result is detected as a leak.
func TestMemoryLeak_NatMallocRecognized(t *testing.T) {
	store := runIndexAndDetect(t, "tc_nat_alloc_leak.c")
	assertHasEvent(t, store, "MEMORY_ALLOC", "tc_nat_alloc_leak")
}

// TestMemoryLeak_ProductionAllocMacros pins the production macro-wrapping
// patterns from docs/req_内存分配释放典型性优化.md: a macro that expands to
// malloc/free or a third-party SDK allocator (VOS_Malloc_F / HpeMemAlloc /
// VOS_Mem_Allock_F / VOS_MemFree_F) must be recognized end-to-end. An unfreed
// allocation through the macro is a leak; a macro/SDK free is a release.
func TestMemoryLeak_ProductionAllocMacros(t *testing.T) {
	store := runIndexAndDetect(t, "tc125_prod_alloc_macros.c")
	allocByFunc, releaseByFunc := countEventsByFunction(t, store, "MEMORY_ALLOC", "MEMORY_RELEASE")

	cases := []struct {
		fn      string
		alloc   int
		release int
	}{
		{"tc125_macro_alloc_free", 1, 1},
		{"tc125_macro_alloc_leak", 1, 0},
		{"tc125_sdk_direct_leak", 1, 0},
		{"tc125_sdk_direct_free", 1, 1},
	}
	for _, c := range cases {
		if allocByFunc[c.fn] != c.alloc || releaseByFunc[c.fn] != c.release {
			t.Errorf("%s: got %d alloc / %d release, want %d alloc / %d release",
				c.fn, allocByFunc[c.fn], releaseByFunc[c.fn], c.alloc, c.release)
		}
	}
}

// TestMemoryLeak_PassthroughAllocWrapper pins the "封装成函数" wrapper pattern:
// a function that returns a malloc'd pointer (even with a custom name lacking
// "alloc"/"malloc" and even using the pointer for NULL-check/memset before the
// return) is itself an allocator. A caller that never frees its result is a leak.
func TestMemoryLeak_PassthroughAllocWrapper(t *testing.T) {
	store := runIndexAndDetect(t, "tc126_passthrough_alloc_wrapper.c")
	allocByFunc, releaseByFunc := countEventsByFunction(t, store, "MEMORY_ALLOC", "MEMORY_RELEASE")

	if allocByFunc["tc126_wrapper_leak"] != 1 || releaseByFunc["tc126_wrapper_leak"] != 0 {
		t.Errorf("tc126_wrapper_leak: got %d alloc / %d release, want 1 alloc / 0 release (custom-named wrapper leak)",
			allocByFunc["tc126_wrapper_leak"], releaseByFunc["tc126_wrapper_leak"])
	}
	if allocByFunc["tc126_wrapper_free"] != 1 || releaseByFunc["tc126_wrapper_free"] != 1 {
		t.Errorf("tc126_wrapper_free: got %d alloc / %d release, want 1 alloc / 1 release",
			allocByFunc["tc126_wrapper_free"], releaseByFunc["tc126_wrapper_free"])
	}
}
