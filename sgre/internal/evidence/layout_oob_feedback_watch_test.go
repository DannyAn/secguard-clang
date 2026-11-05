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
