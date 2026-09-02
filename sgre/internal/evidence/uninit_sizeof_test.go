package evidence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type uninitUse struct {
	function string
	variable string
	origin   string
	line     int
}

func runUninitInline(t *testing.T, src string) []uninitUse {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "uninit_sizeof.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	NewUninitVariableDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "VALUE_USE")
	if err != nil {
		t.Fatalf("list VALUE_USE: %v", err)
	}
	var locIDs []int64
	for _, e := range events {
		if e.LocationID > 0 {
			locIDs = append(locIDs, e.LocationID)
		}
	}
	locs, _ := store.ListLocationsByIDs(ctx, locIDs)

	var out []uninitUse
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		u := uninitUse{variable: props.Variable, origin: props.Origin}
		if loc := locs[e.LocationID]; loc != nil {
			u.line = loc.Line
		}
		if fn, _ := store.GetFunctionByID(ctx, e.EntityID); fn != nil {
			u.function = fn.Name
		}
		out = append(out, u)
	}
	return out
}

// TestUninit_SizeofNotAUse pins that sizeof(val) — and its type form
// sizeof(uint32_t) — are unevaluated type expressions, not reads of val, so the
// reported `uint32_t len = sizeof(val);` must not flag val as uninitialized.
// The control (a genuine read of an uninitialized val) must still be reported.
func TestUninit_SizeofNotAUse(t *testing.T) {
	src := `#include <stdint.h>

int sizeof_var(void)
{
    uint32_t val;
    uint32_t len = sizeof(val);
    return (int)len;
}

int sizeof_type(void)
{
    uint32_t len = sizeof(uint32_t);
    return (int)len;
}

int sizeof_deref(void)
{
    uint32_t val;
    uint32_t len = sizeof(*((uint32_t*)&val));
    return (int)len;
}

int control_genuine_uninit(void)
{
    uint32_t val;
    return (int)val; /* VALUE_USE: genuine read of uninitialized val */
}
`
	uses := runUninitInline(t, src)

	for _, u := range uses {
		if u.variable == "val" && u.function != "control_genuine_uninit" {
			t.Errorf("sizeof must not be reported as a use of uninitialized val: function=%s origin=%s line=%d", u.function, u.origin, u.line)
		}
	}

	controlFound := false
	for _, u := range uses {
		if u.function == "control_genuine_uninit" && u.variable == "val" && u.origin == "stack_uninit" {
			controlFound = true
		}
	}
	if !controlFound {
		t.Errorf("control_genuine_uninit's read of val should still produce a stack_uninit event, got uses=%+v", uses)
	}
}
