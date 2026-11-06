//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
)

// indexAndDetectBufferOverflow indexes a fixture and runs the buffer overflow
// detector with repofacts injected via ctx (mirroring the pipeline flow).
func indexAndDetectBufferOverflow(t *testing.T, fixture string) db.Store {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixture); err != nil {
		t.Fatalf("index %s: %v", fixture, err)
	}

	facts, err := repofacts.Build(ctx, store, p, logger)
	if err != nil {
		t.Fatalf("repofacts build: %v", err)
	}
	ctx = repofacts.WithFacts(ctx, facts)

	_, _ = NewBufferOverflowDetector(store, p, logger).Detect(ctx)
	return store
}

// eventCategory extracts the "category" property from a SecurityEvent.
func eventCategory(e *db.SecurityEvent) string {
	var props struct {
		Category string `json:"category"`
	}
	_ = json.Unmarshal([]byte(e.Properties), &props)
	return props.Category
}

// TestLayoutOOB_CastInsufficientSize pins CWD-SUB-1038 sample A: malloc(8) cast
// to struct LargeRecord (24 bytes), then record->value at offset 16+8=24 > 8.
// The detector must emit a layout_oob_read event.
func TestLayoutOOB_CastInsufficientSize(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "01_cast_insufficient_size.c"))

	events, err := store.ListEventsByType(context.Background(), "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list BUFFER_ACCESS: %v", err)
	}
	found := false
	for _, e := range events {
		if eventCategory(e) == "layout_oob_read" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no layout_oob_read event in %d BUFFER_ACCESS events", len(events))
	}
}

// TestLayoutOOB_CastSufficientSize pins CWD-SUB-1038 sample B (negative):
// malloc(sizeof(struct LargeRecord)) provides exactly enough storage, so NO
// layout_oob event may be emitted. This is the false-positive guard.
func TestLayoutOOB_CastSufficientSize(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "02_cast_sufficient_size.c"))

	events, err := store.ListEventsByType(context.Background(), "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list BUFFER_ACCESS: %v", err)
	}
	for _, e := range events {
		cat := eventCategory(e)
		if cat == "layout_oob_read" || cat == "layout_oob_write" {
			t.Errorf("false positive: layout_oob event on safe allocation (category=%s)", cat)
		}
	}
}

// TestLayoutOOB_NoFalsePositiveOnExistingFixtures verifies the new detector does
// not introduce false positives on the broader buffer-overflow fixture suite.
// It scans every .c file under testdata/feedback_watch/ and asserts no
// layout_oob event appears unless the file is in the 1038 positive set.
func TestLayoutOOB_NoFalsePositiveOnExistingFixtures(t *testing.T) {
	positives := map[string]bool{
		filepath.Join("feedback_watch", "CWD-SUB-1038-invalid-pointer-cast", "01_cast_insufficient_size.c"): true,
		filepath.Join("feedback_watch", "CWD-SUB-1038-invalid-pointer-cast", "09_typedef_cast.c"):           true,
		filepath.Join("feedback_watch", "CWD-SUB-1038-invalid-pointer-cast", "10_layout_oob_write.c"):       true,
		filepath.Join("feedback_watch", "CWD-SUB-1038-invalid-pointer-cast", "13_multidim_array_field.c"):   true,
		filepath.Join("feedback_watch", "CWD-SUB-1038-invalid-pointer-cast", "17_hex_size_literal.c"):       true,
	}
	matches, err := filepath.Glob(filepath.Join("..", "..", "testdata", "feedback_watch", "*", "*.c"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, m := range matches {
		rel, err := filepath.Rel(filepath.Join("..", "..", "testdata"), m)
		if err != nil {
			continue
		}
		store := indexAndDetectBufferOverflow(t, m)
		events, err := store.ListEventsByType(context.Background(), "BUFFER_ACCESS")
		if err != nil {
			t.Fatalf("list events for %s: %v", rel, err)
		}
		for _, e := range events {
			cat := eventCategory(e)
			if cat != "layout_oob_read" && cat != "layout_oob_write" {
				continue
			}
			if !positives[rel] {
				t.Errorf("false positive: layout_oob event on %s (category=%s)", rel, cat)
			}
		}
	}
}

// hasLayoutOOBEvent reports whether the store has a BUFFER_ACCESS event with
// the given category (layout_oob_read or layout_oob_write).
func hasLayoutOOBEvent(t *testing.T, store db.Store, category string) bool {
	t.Helper()
	events, err := store.ListEventsByType(context.Background(), "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list BUFFER_ACCESS: %v", err)
	}
	for _, e := range events {
		if eventCategory(e) == category {
			return true
		}
	}
	return false
}

// TestLayoutOOB_PackedStructNoFalsePositive verifies that a packed struct
// produces NO layout_oob event — the layout is unknown (P0-3), so the
// detector must not guess the field offsets.
func TestLayoutOOB_PackedStructNoFalsePositive(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "05_packed_struct.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("false positive: layout_oob_read on packed struct (layout should be unknown)")
	}
}

// TestLayoutOOB_BitfieldNoFalsePositive verifies that a struct with bitfields
// produces NO layout_oob event — the layout is unknown (P0-4), so the
// detector must not guess the field offsets.
func TestLayoutOOB_BitfieldNoFalsePositive(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "06_bitfield_struct.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("false positive: layout_oob_read on bitfield struct (layout should be unknown)")
	}
}

// TestLayoutOOB_ReassignInvalidates verifies that re-assigning a cast pointer
// to a sufficient allocation invalidates the original insufficient cast
// (P0-5): no layout_oob event after the reassignment.
func TestLayoutOOB_ReassignInvalidates(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "07_reassign_invalidates.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("false positive: layout_oob_read after reassignment to sufficient allocation")
	}
}

// TestLayoutOOB_ArrayFieldSkip verifies that accessing an array field member
// (p->buf[0]) produces NO layout_oob event — array fields are skipped in MVP
// (P0-6) because the access end is the element, not the whole array.
func TestLayoutOOB_ArrayFieldSkip(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "08_array_field_skip.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("false positive: layout_oob_read on array field (should be skipped in MVP)")
	}
}

// TestLayoutOOB_TypedefCast verifies that a cast using a typedef name
// (MyRecord instead of struct LargeRecord) is detected — the layout census
// registers typedef names, and extractStructTagFromType accepts bare names.
func TestLayoutOOB_TypedefCast(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "09_typedef_cast.c"))
	if !hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("expected layout_oob_read for typedef cast with insufficient allocation")
	}
}

// TestLayoutOOB_WriteCategory verifies that a write through a cast pointer
// (record->value = 42) produces a layout_oob_write event, not layout_oob_read.
func TestLayoutOOB_WriteCategory(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "10_layout_oob_write.c"))
	if !hasLayoutOOBEvent(t, store, "layout_oob_write") {
		t.Errorf("expected layout_oob_write for write through cast pointer with insufficient allocation")
	}
}

// TestLayoutOOB_FlexibleArraySkip verifies that an access through a flexible
// array member (payload[]) is skipped: ArrayCount is legitimately 0 for a FAM,
// so the detector must key the skip on IsArray, not on ArrayCount>0. Otherwise
// element size makes `p->payload[0]` look like an out-of-bounds whole-array
// access.
func TestLayoutOOB_FlexibleArraySkip(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "11_flexible_array_skip.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("false positive: layout_oob_read on a flexible-array-member access")
	}
}

// TestLayoutOOB_NestedStructDefinition verifies that an inline nested struct
// definition does not leak its fields into the outer layout. The outer layout is
// {Inner n; uint32_t c} = 12 bytes, so c at offset 8 in malloc(12) is legal. A
// recursive field census would place c at 16 and report a false positive.
func TestLayoutOOB_NestedStructDefinition(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "12_nested_struct_definition.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_write") {
		t.Errorf("false positive: nested struct fields corrupted the outer layout")
	}
}

// TestLayoutOOB_MultidimensionalArrayField verifies that a multi-dimensional
// array member contributes its full size (2*3*4=24) to the layout, so the field
// after it at offset 28 in malloc(28) is a genuine out-of-bounds write.
func TestLayoutOOB_MultidimensionalArrayField(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "13_multidim_array_field.c"))
	if !hasLayoutOOBEvent(t, store, "layout_oob_write") {
		t.Errorf("expected layout_oob_write past a 2x3 array member (multi-dim size must be the product of its dimensions)")
	}
}

// TestLayoutOOB_AllocResolvedAtCastLine verifies that a later reassignment of the
// SOURCE pointer does not retroactively shrink the cast target's allocation: the
// cast record keeps the size that was live at the cast line.
func TestLayoutOOB_AllocResolvedAtCastLine(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "14_alloc_reassigned_after_cast.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("false positive: record still points at the 64-byte allocation after raw was reassigned")
	}
}

// TestLayoutOOB_NewFactoryIsNotAByteSize verifies that a factory whose name
// contains "_new" is not treated as a byte-size allocator: `conn_new(4)` passes a
// version, not a 4-byte allocation.
func TestLayoutOOB_NewFactoryIsNotAByteSize(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "15_new_factory_not_byte_size.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("false positive: conn_new(4) is a factory call, not a 4-byte allocation")
	}
}

// TestLayoutOOB_HexSizeLiteral verifies the C-literal byte-size parser: malloc(0x8U)
// is an 8-byte allocation, not an unparseable expression.
func TestLayoutOOB_HexSizeLiteral(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "17_hex_size_literal.c"))
	if !hasLayoutOOBEvent(t, store, "layout_oob_read") {
		t.Errorf("expected layout_oob_read for malloc(0x8U) cast to a 24-byte struct")
	}
}

// TestLayoutOOB_NestedFieldAccess verifies that `outer->inner.a` is not checked
// at the intermediate `outer->inner` (the whole nested-struct extent). MVP
// supports one-level fields only.
func TestLayoutOOB_NestedFieldAccess(t *testing.T) {
	store := indexAndDetectBufferOverflow(t,
		feedbackWatchPath("CWD-SUB-1038-invalid-pointer-cast", "16_nested_field_access.c"))
	if hasLayoutOOBEvent(t, store, "layout_oob_read") || hasLayoutOOBEvent(t, store, "layout_oob_write") {
		t.Errorf("false positive: leaf outer->inner.a is in bounds, the intermediate outer->inner must not be checked")
	}
}
