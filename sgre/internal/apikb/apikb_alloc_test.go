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

func TestIsDeallocator_FieldFreeNotDirectDeallocator(t *testing.T) {
	for _, name := range []string{"health_free_content", "free_content", "free_list", "set_free_content", "freeze"} {
		if IsDeallocator(name) {
			t.Errorf("IsDeallocator(%q) = true, want false (frees a field / unrelated, not a direct free)", name)
		}
	}
}

func TestAllocatorAndDeallocatorNamePatterns(t *testing.T) {
	for _, name := range []string{"ssl_ctx_new", "x509_dup", "pki_strdup", "pki_util_mem_create"} {
		if !IsAllocator(name) {
			t.Errorf("IsAllocator(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"ctx_destroy", "cache_delete", "list_cleanup", "node_recycle"} {
		if !IsDeallocator(name) {
			t.Errorf("IsDeallocator(%q) = false, want true", name)
		}
	}
	if !IsZeroInitAllocator("ase_zmalloc") || !IsZeroInitAllocator("maf_compile_zmalloc") {
		t.Error("zmalloc wrappers must be zero-initializing allocators")
	}
	if IsZeroInitAllocator("malloc") {
		t.Error("malloc must not be treated as zero-initializing")
	}
	for _, name := range []string{"nlog_en_queue", "list_add", "ctx_put", "cache_register"} {
		if !IsEscapeFunction(name) {
			t.Errorf("IsEscapeFunction(%q) = false, want true", name)
		}
	}
}

func TestIsAllocator_CreateNotMalloc(t *testing.T) {
	for _, name := range []string{
		"pthread_create", "db_create_sync_conn", "db_create_object",
		"cJSON_CreateObject", "cJSON_CreateArray", "create_table_by_type",
		"create_cache_base_addr", "ResourceHandle_create", "LockGuard_create",
	} {
		if IsAllocator(name) {
			t.Errorf("IsAllocator(%q) = true, want false (_create is not a heap malloc)", name)
		}
	}
}

func TestRegisterOwnershipTransfer(t *testing.T) {
	if IsEscapeFunction("dict_set") {
		t.Error("dict_set must not match the built-in naming heuristic")
	}
	RegisterOwnershipTransfer("dict_set")
	if !IsEscapeFunction("dict_set") {
		t.Error("after RegisterOwnershipTransfer, dict_set must be an escape function")
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

// TestDeclaredAllocator_ProductionSdkNames locks in the cross-repo third-party
// allocator/deallocator names documented in
// docs/req_内存分配释放典型性优化.md: VOS_Malloc_F/VOS_Free_F, HpeMemAlloc/HpeMemFree,
// VOS_Mem_Allock_F / VOS_Mem_ReAllock_F / VOS_MemFree_F. They must be PRECISE
// (IsDeclaredAllocator/IsDeclaredDeallocator), not just name-heuristic matches.
func TestDeclaredAllocator_ProductionSdkNames(t *testing.T) {
	for _, name := range []string{"VOS_Malloc_F", "VOS_Mem_Allock_F", "VOS_Mem_ReAllock_F", "HpeMemAlloc"} {
		if !IsDeclaredAllocator(name) {
			t.Errorf("IsDeclaredAllocator(%q) = false, want true (production SDK allocator)", name)
		}
	}
	for _, name := range []string{"VOS_Free_F", "VOS_MemFree_F", "HpeMemFree"} {
		if !IsDeclaredDeallocator(name) {
			t.Errorf("IsDeclaredDeallocator(%q) = false, want true (production SDK deallocator)", name)
		}
	}
}

func TestRegisterAllocator(t *testing.T) {
	RegisterAllocator("__test_only_allocator__")
	if !IsDeclaredAllocator("__test_only_allocator__") {
		t.Error("RegisterAllocator should make it a declared allocator")
	}
}
func TestIsNonNullReturning_BuiltinAndRegistered(t *testing.T) {
	for _, name := range []string{"strerror", "strsignal", "inet_ntoa", "ctermid"} {
		if !IsNonNullReturning(name) {
			t.Errorf("IsNonNullReturning(%q) = false, want true (built-in)", name)
		}
	}
	if IsNonNullReturning("strchr") {
		t.Error("IsNonNullReturning(strchr) = true, want false (strchr is maybe-null, not never-null)")
	}
}

func TestRegisterNonNullReturning(t *testing.T) {
	RegisterNonNullReturning("__test_only_non_null__")
	if !IsNonNullReturning("__test_only_non_null__") {
		t.Error("RegisterNonNullReturning should make it a non-null return")
	}
}

func TestIsKnownNullableReturn_BuiltinPreciseSet(t *testing.T) {
	for _, name := range []string{"strchr", "strstr", "fopen", "getenv", "opendir", "realpath", "gmtime", "dlsym"} {
		if !IsKnownNullableReturn(name) {
			t.Errorf("IsKnownNullableReturn(%q) = false, want true (built-in maybe-null)", name)
		}
	}
	for _, name := range []string{"my_lookup", "get_foo", "strerror", "malloc"} {
		if IsKnownNullableReturn(name) {
			t.Errorf("IsKnownNullableReturn(%q) = true, want false (not in built-in set)", name)
		}
	}
}
