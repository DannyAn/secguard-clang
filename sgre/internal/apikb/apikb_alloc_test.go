package apikb

import "testing"

func TestIsAllocator_ZeroConfigHeuristic(t *testing.T) {
	for _, name := range []string{"malloc", "calloc", "realloc", "nat_malloc", "llm_malloc", "nlog_malloc", "VOS_MALLOC", "VOS_MALLOC_F", "xmalloc", "ngx_alloc"} {
		if !IsAllocator(name) {
			t.Errorf("IsAllocator(%q) = false, want true (built-in or alloc heuristic)", name)
		}
	}
}

func TestIsDeallocator_ZeroConfigHeuristic(t *testing.T) {
	for _, name := range []string{"free", "nat_free", "llm_free", "nlog_free", "VOS_FREE", "VOS_FREE_F", "freeaddrinfo"} {
		if !IsDeallocator(name) {
			t.Errorf("IsDeallocator(%q) = false, want true (built-in or free heuristic)", name)
		}
	}
}

func TestIsDeclaredAllocator_PreciseOnly(t *testing.T) {
	if !IsDeclaredAllocator("malloc") {
		t.Error("IsDeclaredAllocator(malloc) = false, want true")
	}
	if IsDeclaredAllocator("nat_malloc") || IsDeclaredAllocator("pre_malloc_log") {
		t.Error("IsDeclaredAllocator must be precise (built-in/config only), not name-heuristic")
	}
}

func TestRegisterAllocator(t *testing.T) {
	RegisterAllocator("__test_only_allocator__")
	if !IsDeclaredAllocator("__test_only_allocator__") {
		t.Error("RegisterAllocator should make it a declared allocator")
	}
}
