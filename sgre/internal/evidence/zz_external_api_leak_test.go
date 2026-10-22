//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// externalAPITestEvents returns the decoded props of every event of the given
// type whose variable matches, so leak-vs-release assertions stay precise
// (a MEMORY_ALLOC event is emitted on BOTH the leak and the released path).
func externalAPITestEvents(t *testing.T, store db.Store, eventType, variable string) []map[string]string {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, eventType)
	if err != nil {
		t.Fatalf("list %s: %v", eventType, err)
	}
	var out []map[string]string
	for _, e := range events {
		var props map[string]string
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			continue
		}
		if variable == "" || props["variable"] == variable {
			out = append(out, props)
		}
	}
	return out
}

// hasLeakEvent reports whether the variable has a LEAK-shaped MEMORY_ALLOC
// event: the leak branch always sets escape_kind (and free_lines when a
// conditional free exists), while the released branch emits only
// variable/origin/api props.
func hasLeakEvent(t *testing.T, store db.Store, variable string) bool {
	t.Helper()
	for _, props := range externalAPITestEvents(t, store, "MEMORY_ALLOC", variable) {
		if _, isLeak := props["escape_kind"]; isLeak {
			return true
		}
	}
	return false
}

func hasDefiniteLeakEvent(t *testing.T, store db.Store, variable string) bool {
	t.Helper()
	for _, props := range externalAPITestEvents(t, store, "MEMORY_ALLOC", variable) {
		if props["definite"] == "true" {
			return true
		}
	}
	return false
}

// TestExternalAPI_XmlDocPairing covers docs §9.1: a parsed xmlDoc released by
// xmlFreeDoc on all paths is not a leak; an unreleased one is.
func TestExternalAPI_XmlDocPairing(t *testing.T) {
	store := runIndexAndDetect(t, "tc140_xml_read_free.c")
	if hasLeakEvent(t, store, "doc") {
		t.Error("xmlReadMemory + xmlFreeDoc pairing must not report a leak")
	}

	store = runIndexAndDetect(t, "tc141_xml_read_leak.c")
	if !hasDefiniteLeakEvent(t, store, "doc") {
		t.Error("xmlReadMemory with no release and no transfer must be a definite leak candidate")
	}
	for _, props := range externalAPITestEvents(t, store, "MEMORY_ALLOC", "doc") {
		if props["api"] != "xmlReadMemory" {
			t.Errorf("leak event must carry the acquire API xmlReadMemory, got %q", props["api"])
		}
	}
}

// TestExternalAPI_XmlXPathPairing covers docs §9.1: both XPath pairs correct
// (no leak), the result object released with the CONTEXT releaser (mismatch,
// leak), and the context released with plain free() (mismatch, leak — docs
// §6: no generic free substitute).
func TestExternalAPI_XmlXPathPairing(t *testing.T) {
	store := runIndexAndDetect(t, "tc142_xml_xpath_pair.c")
	if hasLeakEvent(t, store, "ctx") || hasLeakEvent(t, store, "obj") {
		t.Error("xmlXPathNewContext↔xmlXPathFreeContext and xmlXPathEvalExpression↔xmlXPathFreeObject pairs must not leak")
	}

	store = runIndexAndDetect(t, "tc143_xml_xpath_mismatch.c")
	if !hasLeakEvent(t, store, "obj") {
		t.Error("xmlXPathFreeContext on an XPath OBJECT must not count as a release; obj leaks")
	}

	store = runIndexAndDetect(t, "tc155_xml_xpath_ctx_wrong_free.c")
	if !hasLeakEvent(t, store, "ctx") {
		t.Error("free() on an XPath context must not count as a release; ctx leaks")
	}
}

// TestExternalAPI_XmlNodeTransfer covers docs §5.1C/§9.1/§9.3: attaching a
// node to a tree exempts it on the unchecked form; the guarded failure
// branch without a fallback release is a CONDITIONAL leak (never definite);
// an orphan node is a leak; an attached namespace escapes with its node.
func TestExternalAPI_XmlNodeTransfer(t *testing.T) {
	store := runIndexAndDetect(t, "tc144_xml_addchild_transfer.c")
	if hasLeakEvent(t, store, "node") {
		t.Error("unchecked xmlAddChild transfer must exempt the node from a leak")
	}

	store = runIndexAndDetect(t, "tc145_xml_addchild_guard_leak.c")
	if !hasLeakEvent(t, store, "node") {
		t.Error("guarded xmlAddChild failure branch without a release must report a leak candidate")
	}
	if hasDefiniteLeakEvent(t, store, "node") {
		t.Error("a conditional transfer channel exists; the guarded-failure leak must stay suspected (non-definite) for the AI")
	}

	store = runIndexAndDetect(t, "tc157_xml_newnode_leak.c")
	if !hasDefiniteLeakEvent(t, store, "node") {
		t.Error("an orphan xmlNewNode with no channel at all must be a definite leak")
	}

	store = runIndexAndDetect(t, "tc153_xml_ns_attach.c")
	if hasLeakEvent(t, store, "ns") {
		t.Error("xmlSetNs attaches the namespace; it must escape with the node, not leak")
	}
}

// TestExternalAPI_CJSONOwnership covers docs §5.2C/§9.1: owning add on the
// unchecked form transfers; failure-branch delete keeps both paths safe;
// guarded failure without delete is a conditional leak; the REFERENCE add
// must NOT transfer; correct pairings never leak.
func TestExternalAPI_CJSONOwnership(t *testing.T) {
	store := runIndexAndDetect(t, "tc146_cjson_add_release_on_fail.c")
	if hasLeakEvent(t, store, "item") || hasLeakEvent(t, store, "o") {
		t.Error("owning add with failure-branch cJSON_Delete must not leak on either path")
	}

	store = runIndexAndDetect(t, "tc147_cjson_add_guard_leak.c")
	if !hasLeakEvent(t, store, "item") {
		t.Error("guarded owning add whose failure branch returns without delete must report a leak candidate")
	}
	if hasDefiniteLeakEvent(t, store, "item") {
		t.Error("a conditional transfer channel exists; the guarded-failure leak must stay suspected")
	}

	store = runIndexAndDetect(t, "tc148_cjson_reference_no_transfer.c")
	if !hasDefiniteLeakEvent(t, store, "item") {
		t.Error("cJSON_AddItemReferenceToObject must NOT transfer: the item still leaks when never deleted")
	}

	store = runIndexAndDetect(t, "tc154_cjson_parse_delete.c")
	if hasLeakEvent(t, store, "root") || hasLeakEvent(t, store, "item") {
		t.Error("cJSON_Parse+cJSON_Delete and unchecked owning add must not leak")
	}

	store = runIndexAndDetect(t, "tc156_cjson_print_free.c")
	if hasLeakEvent(t, store, "s") || hasLeakEvent(t, store, "root") {
		t.Error("free() on cJSON_Print's string is a valid release (cJSON_free is free by default)")
	}
}

// TestExternalAPI_AsprintfSuccessBranch covers docs §5.3/§9.1: the out-param
// allocation exists only on the success branch, so the failure early-return
// (direct guard and assigned-status guard forms) is not leak evidence.
func TestExternalAPI_AsprintfSuccessBranch(t *testing.T) {
	for _, fixture := range []string{"tc149_asprintf_fail_guard.c", "tc150_asprintf_assign_guard.c"} {
		store := runIndexAndDetect(t, fixture)
		if hasLeakEvent(t, store, "p") {
			t.Errorf("%s: asprintf failure early-return must not be leak evidence", fixture)
		}
	}
}

// TestExternalAPI_StrdupWrongFree covers docs §5.3: releasing strdup's block
// with cJSON_Delete is a family mismatch — the string leaks.
func TestExternalAPI_StrdupWrongFree(t *testing.T) {
	store := runIndexAndDetect(t, "tc151_strdup_wrong_free.c")
	if !hasLeakEvent(t, store, "p") {
		t.Error("cJSON_Delete on strdup's block must not count as a release; the string leaks")
	}
}

// TestExternalAPI_FreeBorrowNotAllocation covers docs §5.4/§9.1: strstr's
// borrowed result is not a tracked allocation — no leak is reported and no
// MEMORY_RELEASE is recorded for it (free on a borrow is not a "correct,
// necessary release" the model endorses).
func TestExternalAPI_FreeBorrowNotAllocation(t *testing.T) {
	store := runIndexAndDetect(t, "tc152_free_borrow_no_release.c")
	if hasLeakEvent(t, store, "p") {
		t.Error("strstr's borrowed result must not be reported as a leaked allocation")
	}
	if releases := externalAPITestEvents(t, store, "MEMORY_RELEASE", "p"); len(releases) > 0 {
		t.Errorf("free() on a borrowed pointer must not be recorded as a valid release, got %d MEMORY_RELEASE events", len(releases))
	}
}

// TestExternalAPI_XmlTreeInternalNodesNotLeakedWhenDocReleased locks the
// "document manages its tree" rule from docs §6 at the detector level: a
// node obtained from the document (a BORROW) that is never freed while the
// document is must not produce a phantom allocation. The borrowed root's
// unguarded dereference is covered separately in the null-deref suite.
func TestExternalAPI_XmlTreeInternalNodesNotLeakedWhenDocReleased(t *testing.T) {
	store := runIndexAndDetect(t, "tc158_external_nullable_deref.c")
	if hasLeakEvent(t, store, "root") {
		t.Error("xmlDocGetRootElement's borrowed root must not be tracked as a fresh allocation")
	}
	if hasLeakEvent(t, store, "item") {
		t.Error("cJSON_GetObjectItem's borrowed item must not be tracked as a fresh allocation")
	}
	if hasLeakEvent(t, store, "doc") || hasLeakEvent(t, store, "obj") {
		t.Error("correctly paired xmlDoc/cJSON roots must not leak")
	}
}

// hasFreeOnBorrowEvent reports whether the variable has a free-on-borrow
// candidate event: a deallocator call on the result of a borrowed-return API
// (cJSON_GetObjectItem → cJSON_Delete, strstr → free).
func hasFreeOnBorrowEvent(t *testing.T, store db.Store, variable string) bool {
	t.Helper()
	for _, props := range externalAPITestEvents(t, store, "MEMORY_ALLOC", variable) {
		if props["origin"] == "free-borrow" {
			return true
		}
	}
	return false
}

// TestExternalAPI_CJSONStandardUsage locks the user-provided canonical
// create/attach/print/release form (tc159): three ownership rules exercised
// and zero findings on every channel — no leak for root/name/json, and no
// free-on-borrow candidate for any of them.
func TestExternalAPI_CJSONStandardUsage(t *testing.T) {
	store := runIndexAndDetect(t, "tc159_cjson_standard_usage.c")
	for _, v := range []string{"root", "name", "json"} {
		if hasLeakEvent(t, store, v) {
			t.Errorf("%s: the standard create/attach/print/release form must not report a leak", v)
		}
		if hasFreeOnBorrowEvent(t, store, v) {
			t.Errorf("%s: correctly-paired objects must not raise a free-on-borrow candidate", v)
		}
	}
}

// TestExternalAPI_CJSONDeleteBorrowedItem locks the user-provided misuse
// (tc160): deleting an item borrowed from the parent tree. The root itself
// stays correctly paired (no false leak), and the free-on-borrow channel
// must surface a candidate for `name` — releasing an object the caller does
// not own is an invalid-free/UAF risk.
func TestExternalAPI_CJSONDeleteBorrowedItem(t *testing.T) {
	store := runIndexAndDetect(t, "tc160_cjson_delete_borrowed.c")
	if hasLeakEvent(t, store, "root") {
		t.Error("cJSON_Parse + cJSON_Delete keeps the root correctly paired; no false leak")
	}
	if hasLeakEvent(t, store, "name") {
		t.Error("the borrowed item is not an allocation; the finding must be free-on-borrow, not a leak")
	}
	if !hasFreeOnBorrowEvent(t, store, "name") {
		t.Error("cJSON_Delete on cJSON_GetObjectItem's borrowed result must surface a free-on-borrow candidate")
	}
	for _, props := range externalAPITestEvents(t, store, "MEMORY_ALLOC", "name") {
		if props["origin"] == "free-borrow" {
			if props["api"] != "cJSON_GetObjectItem" {
				t.Errorf("free-on-borrow event must carry the borrow source API, got %q", props["api"])
			}
			if props["borrow_free"] != "cJSON_Delete" {
				t.Errorf("free-on-borrow event must carry the releasing call, got %q", props["borrow_free"])
			}
		}
	}
}

// TestExternalAPI_CJSONDetach covers the Detach family (user-provided form):
// the detached item is caller-owned (needs its own delete), unlike Get which
// only borrows. Correct pairing must stay silent; a detached item never
// deleted is a definite leak the root's delete does NOT cover.
func TestExternalAPI_CJSONDetach(t *testing.T) {
	store := runIndexAndDetect(t, "tc161_cjson_detach_ok.c")
	if hasLeakEvent(t, store, "name") || hasLeakEvent(t, store, "root") {
		t.Error("Detach + cJSON_Delete + cJSON_Delete(root) is correctly paired on both chains")
	}
	if hasFreeOnBorrowEvent(t, store, "name") {
		t.Error("a detached item is caller-owned; deleting it must not raise free-on-borrow")
	}

	store = runIndexAndDetect(t, "tc162_cjson_detach_leak.c")
	if !hasDefiniteLeakEvent(t, store, "name") {
		t.Error("a detached item never deleted is a definite leak (the root's delete no longer covers it)")
	}
	if hasLeakEvent(t, store, "root") {
		t.Error("the root stays correctly paired in the detach-leak case")
	}
}

// TestExternalAPI_CJSONAddThenDeleteItemBoundary locks the boundary semantics
// (tc163): after a checked owning add succeeds, the item belongs to the
// parent. The cross-object double free is out of the leak detector's scope —
// the leak channel must stay silent for both the item and the root (no
// false leak, no fabricated conclusion either way).
func TestExternalAPI_CJSONAddThenDeleteItemBoundary(t *testing.T) {
	store := runIndexAndDetect(t, "tc163_cjson_add_then_delete.c")
	if hasLeakEvent(t, store, "name") || hasLeakEvent(t, store, "root") {
		t.Error("the add-then-delete boundary must not fabricate a leak on either object")
	}
	if hasFreeOnBorrowEvent(t, store, "name") {
		t.Error("name is a created (owned) item, not a borrow; free-on-borrow must not fire")
	}
}

// TestExternalAPI_FreeOnBorrowStrchr extends tc152: free() on strstr's
// borrowed result is now surfaced as a free-on-borrow candidate (an invalid
// free of a pointer into the input string), in addition to staying off the
// leak and release channels.
func TestExternalAPI_FreeOnBorrowStrchr(t *testing.T) {
	store := runIndexAndDetect(t, "tc152_free_borrow_no_release.c")
	if hasLeakEvent(t, store, "p") {
		t.Error("strstr's borrowed result must not be reported as a leaked allocation")
	}
	if releases := externalAPITestEvents(t, store, "MEMORY_RELEASE", "p"); len(releases) > 0 {
		t.Errorf("free() on a borrowed pointer must not be recorded as a valid release, got %d MEMORY_RELEASE events", len(releases))
	}
	if !hasFreeOnBorrowEvent(t, store, "p") {
		t.Error("free() on strstr's borrowed result must surface a free-on-borrow candidate")
	}
}
