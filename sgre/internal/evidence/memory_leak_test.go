package evidence

import (
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
