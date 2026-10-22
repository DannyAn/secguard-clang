package apikb

import "testing"

// TestExternalAPI_Libxml2Pairing locks the documented release pairing
// (docs §5.1/§6): document, node, namespace, XPath context, and XPath object
// are distinct object types with distinct releasers that must never be
// interchanged.
func TestExternalAPI_Libxml2Pairing(t *testing.T) {
	cases := []struct {
		alloc      string
		validFrees []string
	}{
		{"xmlNewDoc", []string{"xmlFreeDoc"}},
		{"xmlReadMemory", []string{"xmlFreeDoc"}},
		{"xmlReadFile", []string{"xmlFreeDoc"}},
		{"xmlParseDoc", []string{"xmlFreeDoc"}},
		{"xmlNewNode", []string{"xmlFreeNode", "xmlFreeNodeList"}},
		{"xmlNewNs", []string{"xmlFreeNs"}},
		{"xmlXPathNewContext", []string{"xmlXPathFreeContext"}},
		{"xmlXPathEvalExpression", []string{"xmlXPathFreeObject"}},
		{"xmlXPathEval", []string{"xmlXPathFreeObject"}},
		{"xmlXPathCompiledEval", []string{"xmlXPathFreeObject"}},
	}
	for _, tc := range cases {
		s, ok := ExternalAPISpecByName(tc.alloc)
		if !ok {
			t.Errorf("%s: not modeled", tc.alloc)
			continue
		}
		if s.Alloc != AllocRet {
			t.Errorf("%s: Alloc = %v, want AllocRet", tc.alloc, s.Alloc)
		}
		if s.RetNull != RetNullMay {
			t.Errorf("%s: RetNull = %v, want RetNullMay", tc.alloc, s.RetNull)
		}
		if len(s.ValidFrees) != len(tc.validFrees) {
			t.Errorf("%s: ValidFrees = %v, want %v", tc.alloc, s.ValidFrees, tc.validFrees)
			continue
		}
		for i, f := range tc.validFrees {
			if s.ValidFrees[i] != f {
				t.Errorf("%s: ValidFrees[%d] = %q, want %q", tc.alloc, i, s.ValidFrees[i], f)
			}
		}
		if s.AllowGenericFree || s.UnrestrictedRelease {
			t.Errorf("%s: libxml2 allocations must not accept generic/unrestricted release", tc.alloc)
		}
	}
}

// TestExternalAPI_Libxml2Releasers locks the modeled libxml2 releasers.
func TestExternalAPI_Libxml2Releasers(t *testing.T) {
	for _, name := range []string{
		"xmlFreeDoc", "xmlFreeNode", "xmlFreeNodeList", "xmlFreeNs",
		"xmlXPathFreeContext", "xmlXPathFreeObject", "xmlFree",
	} {
		if !IsDeclaredDeallocator(name) {
			t.Errorf("IsDeclaredDeallocator(%q) = false, want true (modeled libxml2 releaser)", name)
		}
		s, ok := ExternalAPISpecByName(name)
		if !ok || !s.Releases {
			t.Errorf("%s: Releases missing from model", name)
			continue
		}
		if s.FreeArgIdx != 0 {
			t.Errorf("%s: FreeArgIdx = %d, want 0", name, s.FreeArgIdx)
		}
	}
}

// TestExternalAPI_CJSONPairing locks the cJSON pairing: every Create*/Parse*/
// Duplicate result is released by cJSON_Delete only; the Print* string by
// cJSON_free (free is equivalent per the 1.7 readme).
func TestExternalAPI_CJSONPairing(t *testing.T) {
	deleteOnly := []string{
		"cJSON_CreateObject", "cJSON_CreateArray", "cJSON_CreateString",
		"cJSON_CreateNumber", "cJSON_CreateDouble", "cJSON_CreateBool",
		"cJSON_CreateNull", "cJSON_CreateTrue", "cJSON_CreateFalse",
		"cJSON_CreateRaw", "cJSON_CreateArrayReference", "cJSON_CreateObjectReference",
		"cJSON_Duplicate", "cJSON_Parse", "cJSON_ParseWithLength", "cJSON_ParseWithOpts",
	}
	for _, name := range deleteOnly {
		s, ok := ExternalAPISpecByName(name)
		if !ok {
			t.Errorf("%s: not modeled", name)
			continue
		}
		if s.Alloc != AllocRet || s.RetNull != RetNullMay {
			t.Errorf("%s: want AllocRet+RetNullMay, got Alloc=%v RetNull=%v", name, s.Alloc, s.RetNull)
		}
		if len(s.ValidFrees) != 1 || s.ValidFrees[0] != "cJSON_Delete" {
			t.Errorf("%s: ValidFrees = %v, want [cJSON_Delete]", name, s.ValidFrees)
		}
		if s.AllowGenericFree || s.UnrestrictedRelease {
			t.Errorf("%s: free() on a cJSON tree releases only the top node; generic release must be rejected", name)
		}
	}
	for _, name := range []string{"cJSON_Print", "cJSON_PrintUnformatted", "cJSON_PrintBuffered"} {
		s, ok := ExternalAPISpecByName(name)
		if !ok {
			t.Errorf("%s: not modeled", name)
			continue
		}
		if len(s.ValidFrees) != 1 || s.ValidFrees[0] != "cJSON_free" {
			t.Errorf("%s: ValidFrees = %v, want [cJSON_free]", name, s.ValidFrees)
		}
		if !s.AllowGenericFree {
			t.Errorf("%s: cJSON_free is free() by default; generic free must be legal", name)
		}
	}
	for _, name := range []string{"cJSON_Delete", "cJSON_free"} {
		if !IsDeclaredDeallocator(name) {
			t.Errorf("IsDeclaredDeallocator(%q) = false, want true", name)
		}
	}
}

// TestExternalAPI_OwnershipSemantics locks the owning-add vs reference-add
// distinction (docs §5.2C) and the libxml2 tree-attach transfers.
func TestExternalAPI_OwnershipSemantics(t *testing.T) {
	owning := map[string]int{
		"cJSON_AddItemToArray":    1,
		"cJSON_AddItemToObject":   2,
		"cJSON_AddItemToObjectCS": 2,
		"xmlDocSetRootElement":    1,
		"xmlAddChild":             1,
		"xmlAddSibling":           1,
	}
	for name, argIdx := range owning {
		kind, idx, ok := EscapeOwnership(name)
		if !ok || kind != OwnershipTransferOnSuccess {
			t.Errorf("EscapeOwnership(%q) = (%v,%d), want TransferOnSuccess", name, kind, idx)
			continue
		}
		if idx != argIdx {
			t.Errorf("EscapeOwnership(%q).OwnArgIdx = %d, want %d", name, idx, argIdx)
		}
		if !IsEscapeFunction(name) {
			t.Errorf("IsEscapeFunction(%q) = false, want true (conditional transfer still escapes on the unchecked form)", name)
		}
	}
	kind, _, ok := EscapeOwnership("xmlSetNs")
	if !ok || kind != OwnershipTransferAlways {
		t.Errorf("EscapeOwnership(xmlSetNs) = %v, want TransferAlways (version-difference conservative choice)", kind)
	}
	// Reference adds must NOT transfer (they must also override the `_add`
	// naming heuristic, which would otherwise misread them).
	for _, name := range []string{"cJSON_AddItemReferenceToArray", "cJSON_AddItemReferenceToObject"} {
		kind, _, ok := EscapeOwnership(name)
		if !ok || kind != OwnershipBorrow {
			t.Errorf("EscapeOwnership(%q) = (%v,%v), want Borrow", name, kind, ok)
		}
		if IsEscapeFunction(name) {
			t.Errorf("IsEscapeFunction(%q) = true, want false (reference add keeps caller ownership)", name)
		}
	}
}

// TestExternalAPI_CJSONDetachVsGet locks the detach-vs-get distinction
// (user-provided semantics table): Detach hands the item's ownership to the
// caller (a caller-acquired allocation paired with cJSON_Delete), while Get
// only borrows (possibly NULL, never owned, never freed by the caller).
func TestExternalAPI_CJSONDetachVsGet(t *testing.T) {
	for _, name := range []string{"cJSON_DetachItemFromObject", "cJSON_DetachItemFromObjectCaseSensitive", "cJSON_DetachItemFromArray"} {
		s, ok := ExternalAPISpecByName(name)
		if !ok {
			t.Errorf("%s: not modeled", name)
			continue
		}
		if s.Alloc != AllocRet || s.RetNull != RetNullMay {
			t.Errorf("%s: want AllocRet+RetNullMay (detached item is caller-owned and detach may fail), got Alloc=%v RetNull=%v", name, s.Alloc, s.RetNull)
		}
		if len(s.ValidFrees) != 1 || s.ValidFrees[0] != "cJSON_Delete" {
			t.Errorf("%s: ValidFrees = %v, want [cJSON_Delete]", name, s.ValidFrees)
		}
		if s.RetBorrow {
			t.Errorf("%s: a detached item is owned by the caller, not borrowed", name)
		}
		if !IsDeclaredAllocator(name) {
			t.Errorf("IsDeclaredAllocator(%q) = false, want true (detach acquires ownership)", name)
		}
	}
}

// TestExternalAPI_BorrowReturns locks the nullable-borrow lookups (docs §5.1D,
// §5.2A): possibly NULL, but never a fresh allocation owned by the caller.
func TestExternalAPI_BorrowReturns(t *testing.T) {
	for _, name := range []string{
		"xmlDocGetRootElement", "xmlFirstElementChild", "xmlNextElementSibling",
		"cJSON_GetObjectItem", "cJSON_GetObjectItemCaseSensitive", "cJSON_GetArrayItem",
	} {
		s, ok := ExternalAPISpecByName(name)
		if !ok {
			t.Errorf("%s: not modeled", name)
			continue
		}
		if s.RetNull != RetNullMay || !s.RetBorrow {
			t.Errorf("%s: want RetNullMay+RetBorrow, got RetNull=%v RetBorrow=%v", name, s.RetNull, s.RetBorrow)
		}
		if s.Alloc != AllocNone {
			t.Errorf("%s: a borrow must not be modeled as an allocation", name)
		}
		if !IsKnownNullableReturn(name) {
			t.Errorf("IsKnownNullableReturn(%q) = false, want true", name)
		}
		if !IsBorrowReturn(name) {
			t.Errorf("IsBorrowReturn(%q) = false, want true", name)
		}
	}
}

// TestExternalAPI_LegacyQueryShims locks that the model feeds the legacy
// name-keyed queries: modeled allocators/nullables are precise (declared)
// matches, and unmodeled `_create` names keep failing the heuristic.
func TestExternalAPI_LegacyQueryShims(t *testing.T) {
	for _, name := range []string{
		"xmlNewDoc", "xmlNewNode", "xmlNewNs", "xmlReadMemory", "xmlReadFile",
		"xmlXPathNewContext", "xmlXPathEvalExpression",
		"cJSON_CreateObject", "cJSON_Parse", "cJSON_Duplicate", "cJSON_Print",
	} {
		if !IsDeclaredAllocator(name) {
			t.Errorf("IsDeclaredAllocator(%q) = false, want true (model)", name)
		}
		if !IsAllocator(name) {
			t.Errorf("IsAllocator(%q) = false, want true", name)
		}
		if !IsKnownNullableReturn(name) {
			t.Errorf("IsKnownNullableReturn(%q) = false, want true (allocator failure is a documented maybe-NULL)", name)
		}
	}
	// Unmodeled `_create` names must stay heuristic misses (the model made
	// cJSON_CreateObject a PRECISE match; the heuristic still must not be
	// widened to every _create).
	for _, name := range []string{"pthread_create", "db_create_sync_conn", "foo_create"} {
		if IsAllocator(name) {
			t.Errorf("IsAllocator(%q) = true, want false (_create heuristic miss)", name)
		}
	}
}

// TestExternalAPI_ReleasePolicyMatrix locks the pairing rules (docs §6):
// libxml2/cJSON specialized allocations reject foreign releasers including
// plain free(); strdup accepts free but rejects specialized releasers;
// malloc accepts anything; unmodeled allocators accept anything.
func TestExternalAPI_ReleasePolicyMatrix(t *testing.T) {
	type pair struct {
		alloc, release string
		valid          bool
	}
	cases := []pair{
		{"xmlXPathEvalExpression", "xmlXPathFreeObject", true},
		{"xmlXPathEvalExpression", "xmlXPathFreeContext", false},
		{"xmlXPathEvalExpression", "free", false},
		{"xmlXPathNewContext", "xmlXPathFreeContext", true},
		{"xmlXPathNewContext", "xmlXPathFreeObject", false},
		{"xmlXPathNewContext", "free", false},
		{"xmlNewDoc", "xmlFreeDoc", true},
		{"xmlNewDoc", "xmlFreeNode", false},
		{"xmlNewDoc", "free", false},
		{"xmlReadMemory", "xmlFreeDoc", true},
		{"xmlReadMemory", "xmlFreeNode", false},
		{"xmlNewNode", "xmlFreeNode", true},
		{"xmlNewNode", "xmlFreeNodeList", true},
		{"xmlNewNode", "xmlFreeDoc", false},
		{"cJSON_Parse", "cJSON_Delete", true},
		{"cJSON_Parse", "free", false},
		{"cJSON_Parse", "cJSON_free", false},
		{"cJSON_Print", "cJSON_free", true},
		{"cJSON_Print", "free", true},
		{"cJSON_Print", "cJSON_Delete", false},
		{"strdup", "free", true},
		{"strdup", "cJSON_Delete", false},
		{"strdup", "xmlFreeDoc", false},
		{"malloc", "free", true},
		{"malloc", "cJSON_Delete", true},
		{"malloc", "xmlFreeDoc", true},
		{"nat_malloc", "nat_free", true},
		{"my_alloc_wrapper", "free", true},
	}
	for _, tc := range cases {
		p := AllocatorReleasePolicy(tc.alloc)
		if got := p.Releases(tc.release); got != tc.valid {
			t.Errorf("policy(%s).Releases(%s) = %v, want %v", tc.alloc, tc.release, got, tc.valid)
		}
	}
}

// TestExternalAPI_OutParamAllocators locks the output-parameter allocator
// channel (docs §5.3): asprintf/vasprintf/getline/getdelim write the
// allocation into arg 0 and their RETURN value is a status code, never a
// pointer.
func TestExternalAPI_OutParamAllocators(t *testing.T) {
	for _, name := range []string{"asprintf", "vasprintf", "getline", "getdelim"} {
		idx, ok := IsOutParamAllocator(name)
		if !ok || idx != 0 {
			t.Errorf("IsOutParamAllocator(%q) = (%d,%v), want (0,true)", name, idx, ok)
		}
		s, _ := ExternalAPISpecByName(name)
		if s.RetNull != RetNullUnknown {
			t.Errorf("%s: return is a status code, not a pointer; RetNull must be unknown, got %v", name, s.RetNull)
		}
		p := AllocatorReleasePolicy(name)
		if !p.Releases("free") {
			t.Errorf("%s: free() must validly release the out-param allocation", name)
		}
		if p.Releases("xmlFreeDoc") || p.Releases("cJSON_Delete") {
			t.Errorf("%s: a specialized releaser must be a mismatch", name)
		}
	}
	for _, name := range []string{"malloc", "strdup", "xmlNewDoc", "cJSON_Parse"} {
		if _, ok := IsOutParamAllocator(name); ok {
			t.Errorf("IsOutParamAllocator(%q) = true, want false", name)
		}
	}
}

// TestExternalAPI_AcceptsNullAudit locks the audit dimension: only free()
// has an explicit NULL-safety contract (C89); the library releasers do not
// document one and must stay false rather than guessed true.
func TestExternalAPI_AcceptsNullAudit(t *testing.T) {
	s, ok := ExternalAPISpecByName("free")
	if !ok || !s.AcceptsNull {
		t.Error("free: AcceptsNull must be true (C89)")
	}
	for _, name := range []string{
		"xmlFreeDoc", "xmlFreeNode", "xmlXPathFreeContext", "xmlXPathFreeObject",
		"cJSON_Delete", "cJSON_free",
	} {
		s, ok := ExternalAPISpecByName(name)
		if !ok {
			t.Fatalf("%s: not modeled", name)
		}
		if s.AcceptsNull {
			t.Errorf("%s: AcceptsNull = true without a documented contract", name)
		}
	}
}

// TestExternalAPI_ModelCoversFirstBatchDocs sanity-checks the first-batch
// lists from docs §5 so a rename or accidental deletion in the table fails
// loudly.
func TestExternalAPI_ModelCoversFirstBatchDocs(t *testing.T) {
	required := []string{
		// libxml2 creation/parsing.
		"xmlNewNode", "xmlNewDoc", "xmlReadMemory", "xmlReadFile",
		"xmlXPathNewContext", "xmlXPathEvalExpression", "xmlNewNs",
		// libxml2 release.
		"xmlFreeDoc", "xmlFreeNode", "xmlFreeNodeList", "xmlFreeNs",
		"xmlXPathFreeContext", "xmlXPathFreeObject",
		// libxml2 ownership/tree.
		"xmlDocSetRootElement", "xmlAddChild", "xmlAddSibling",
		// libxml2 borrowed navigation.
		"xmlDocGetRootElement", "xmlNextElementSibling", "xmlFirstElementChild",
		// cJSON creation/parsing.
		"cJSON_CreateObject", "cJSON_CreateArray", "cJSON_CreateString",
		"cJSON_Duplicate", "cJSON_Parse", "cJSON_GetObjectItem", "cJSON_GetArrayItem",
		// cJSON release.
		"cJSON_Delete", "cJSON_free",
		// cJSON add.
		"cJSON_AddItemToArray", "cJSON_AddItemToObject",
		"cJSON_AddItemReferenceToArray", "cJSON_AddItemReferenceToObject",
		// libc heap.
		"strdup", "strndup", "asprintf", "vasprintf",
	}
	for _, name := range required {
		if _, ok := ExternalAPISpecByName(name); !ok {
			t.Errorf("%s: required by docs §5 first batch but not modeled", name)
		}
	}
	// The libc §5.4 nullable non-owning set (strstr/strchr/strrchr/getenv/
	// setlocale) is carried by BuiltinNullableReturning AND now modeled with
	// RetBorrow so the free-on-borrow channel recognizes them (free() on
	// strstr's in-string pointer is an invalid free). Nullable behavior is
	// unchanged — the model tier and the builtin tier agree.
	for _, name := range []string{"strstr", "strchr", "strrchr", "getenv", "setlocale"} {
		if !IsKnownNullableReturn(name) {
			t.Errorf("IsKnownNullableReturn(%q) = false, want true (libc §5.4)", name)
		}
		if !IsBorrowReturn(name) {
			t.Errorf("IsBorrowReturn(%q) = false, want true (borrowed view of input/environment storage)", name)
		}
		if IsAllocator(name) && !IsDeclaredAllocator(name) {
			t.Errorf("%s must not match the allocator heuristic", name)
		}
	}
	// The wider libc search family stays unmodeled (unknown, not guessed).
	for _, name := range []string{"strpbrk", "memchr", "strtok"} {
		if IsBorrowReturn(name) {
			t.Errorf("IsBorrowReturn(%q) = true; unmodeled search family must stay unknown", name)
		}
	}
}
