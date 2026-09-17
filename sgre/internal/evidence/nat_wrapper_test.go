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
