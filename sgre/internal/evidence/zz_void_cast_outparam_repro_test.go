package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUncheckedReturn_VoidCastOutParam verifies that a (void) cast on an
// allocator-name heuristic match (HpeDynmemAlloc) is respected as the
// programmer's "intentionally ignoring" annotation, while a (void) cast on a
// declared allocator (malloc) is still flagged as CWE-252.
//
// Regression for the user-reported false positive:
//
//	(void)HpeDynmemAlloc(g_dslitecar_dynm_id, &new_node);
//	if (new_node == NULL) { return NULL; }
//
// HpeDynmemAlloc returns void* (so it passes the pointer-return gate) and is
// matched by the "alloc" substring heuristic, but it allocates through an
// out-parameter; the (void) cast says the return value is not the allocation
// result the caller cares about.
func TestUncheckedReturn_VoidCastOutParam(t *testing.T) {
	store := runOneDetector(t, "tc_unchecked_return_void_cast_outparam.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUncheckedReturnDetector(s, p, l) })
	events, err := store.ListEventsByType(context.Background(), "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	seenHpeDynmemAlloc := false
	seenVoidMalloc := false
	for _, e := range events {
		var props struct {
			Function string `json:"function"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		switch props.Function {
		case "HpeDynmemAlloc":
			seenHpeDynmemAlloc = true
		case "malloc":
			if e.EntityID == 4 {
				seenVoidMalloc = true
			}
		}
	}

	if seenHpeDynmemAlloc {
		t.Error("(void)HpeDynmemAlloc(...) was flagged as unchecked-return — a (void) cast on an allocator-heuristic function should be respected")
	}
	if !seenVoidMalloc {
		t.Error("(void)malloc(100) was NOT flagged — a (void) cast on a declared allocator must still be reported")
	}
}
