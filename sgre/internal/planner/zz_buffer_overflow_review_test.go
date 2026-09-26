//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// planBO runs the full pipeline for buffer-overflow / out-of-bounds and returns
// the converged candidates keyed by function name.
func planBO(t *testing.T, src, vulnType string) map[string]EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "bo.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)
	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, vulnType)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	out := map[string]EvidenceItem{}
	for _, c := range res.Candidates {
		out[c.Target.Function] = c
	}
	return out
}

// BO-06: hex and suffixed constant indices are provable OOB.
func TestBOverflow_ConstantIndexRadix(t *testing.T) {
	src := `int hex_oob(void) { int arr[10]; arr[0x10] = 0; return 0; }
int suffix_oob(void) { int arr[10]; arr[10u] = 0; return 0; }
int hex_ok(void) { int arr[10]; arr[0x5] = 0; return 0; }
`
	got := planBO(t, src, "buffer-overflow")
	if got["hex_oob"].Target.Function == "" {
		t.Errorf("hex_oob: arr[0x10] into int[10] must be OOB, got %v", keysOf(got))
	}
	if got["suffix_oob"].Target.Function == "" {
		t.Errorf("suffix_oob: arr[10u] into int[10] must be OOB, got %v", keysOf(got))
	}
	if got["hex_ok"].Target.Function != "" {
		t.Errorf("hex_ok: arr[0x5] into int[10] is in-bounds, got %q", got["hex_ok"].Target.Function)
	}
}

// BO-05: a macro loop bound `i <= SIZE` is provable OOB.
func TestBOverflow_MacroLoopBound(t *testing.T) {
	src := `#define SIZE 10
int macro_oob(void) {
    int arr[SIZE];
    for (int i = 0; i <= SIZE; i++) arr[i] = 0;
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["macro_oob"].Target.Function == "" {
		t.Errorf("macro_oob: i<=SIZE (SIZE=10) overruns int[10], got %v", keysOf(got))
	}
}

// BO-11: the loop index offset is modeled — arr[i-1] is safe, arr[i+1] overruns.
func TestBOverflow_LoopIndexOffset(t *testing.T) {
	src := `int safe_offset(void) {
    int arr[10];
    for (int i = 1; i <= 10; i++) arr[i - 1] = 0;
    return 0;
}
int oob_offset(void) {
    int arr[10];
    for (int i = 0; i < 10; i++) arr[i + 1] = 0;
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["safe_offset"].Target.Function != "" {
		t.Errorf("safe_offset: arr[i-1] with i<=10 is in-bounds [0,9], got %q", got["safe_offset"].Target.Function)
	}
	if got["oob_offset"].Target.Function == "" {
		t.Errorf("oob_offset: arr[i+1] with i<10 touches arr[10], got %v", keysOf(got))
	}
}

// BO-12: read/recv/fread with a sizeof/capacity-bounded size are safe idioms.
func TestBOverflow_ReadFamily(t *testing.T) {
	src := `#include <unistd.h>
#include <stdio.h>
int safe_read(int fd) {
    char buf[64];
    return read(fd, buf, sizeof(buf));
}
int safe_fread(int fd) {
    char buf[64];
    return fread(buf, 1, 64, 0);
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["safe_read"].Target.Function != "" {
		t.Errorf("safe_read: read(fd, buf, sizeof(buf)) is bounded, got %q", got["safe_read"].Target.Function)
	}
	if got["safe_fread"].Target.Function != "" {
		t.Errorf("safe_fread: fread(buf, 1, 64) fits char[64], got %q", got["safe_fread"].Target.Function)
	}
}

// BO-13: malloc(n*sizeof(int)) then memcpy(..., n) copies n bytes into a larger
// buffer — byte/element units are now normalized.
func TestBOverflow_ElementByteUnits(t *testing.T) {
	src := `#include <stdlib.h>
#include <string.h>
int unit_ok(void) {
    int *p = malloc(16 * sizeof(int));
    memcpy(p, "x", 16);
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["unit_ok"].Target.Function != "" {
		t.Errorf("unit_ok: memcpy(16 bytes) into malloc(16*sizeof(int)) is safe, got %q", got["unit_ok"].Target.Function)
	}
}

// BO-16: a pure-literal format string overflow is provable (format_overflow).
func TestBOverflow_FormatLiteral(t *testing.T) {
	src := `#include <stdio.h>
int literal_fmt(void) {
    char buf[8];
    sprintf(buf, "this literal is far longer than eight");
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["literal_fmt"].Target.Function == "" {
		t.Errorf("literal_fmt: a 40-char literal into char[8] must be format_overflow, got %v", keysOf(got))
	}
}

// BO-04: an unrelated `if (x < size) { y = 1; }` must NOT suppress a memcpy.
func TestBOverflow_UnrelatedBoundsCheck(t *testing.T) {
	src := `#include <string.h>
int unrelated_guard(int x, int size) {
    char dst[8];
    char src[64];
    if (x < size) { x = 1; }
    memcpy(dst, src, 64);
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["unrelated_guard"].Target.Function == "" {
		t.Errorf("unrelated_guard: memcpy(dst, src, 64) into char[8] must be reported, got %v", keysOf(got))
	}
}

// BO-09: memcpy(&dst, src, sizeof(*src)) copies the SOURCE size, not a value copy.
func TestBOverflow_MemcpySourceSizeof(t *testing.T) {
	src := `#include <string.h>
int src_sizeof(void) {
    char dst[4];
    char src[64];
    memcpy(&dst, src, sizeof(*src));
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["src_sizeof"].Target.Function == "" {
		t.Errorf("src_sizeof: memcpy(&dst, src, sizeof(*src)) copies 64 bytes into char[4], got %v", keysOf(got))
	}
}

// BO-10: a pointer dereference `*(arr + i)` is the same access as `arr[i]` and is
// checked for OOB.
func TestBOverflow_PointerDerefOOB(t *testing.T) {
	src := `int deref_oob(void) {
    int arr[10];
    for (int i = 0; i <= 10; i++) *(arr + i) = 0;
    return 0;
}
int deref_ok(void) {
    int arr[10];
    for (int i = 0; i < 10; i++) *(arr + i) = 0;
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	if got["deref_oob"].Target.Function == "" {
		t.Errorf("deref_oob: *(arr+i) with i<=10 overruns int[10], got %v", keysOf(got))
	}
	if got["deref_ok"].Target.Function != "" {
		t.Errorf("deref_ok: *(arr+i) with i<10 is in-bounds, got %q", got["deref_ok"].Target.Function)
	}
}

// BO-01/02: the range-oob filter independently confirms a constant index past the
// array bound via the interval engine.
func TestBOverflow_RangeConfirmed(t *testing.T) {
	src := `int range_confirmed(void) {
    int arr[10];
    arr[0x10] = 0;
    return 0;
}
`
	got := planBO(t, src, "buffer-overflow")
	c, ok := got["range_confirmed"]
	if !ok {
		t.Fatalf("range_confirmed: arr[0x10] into int[10] must be a candidate, got %v", keysOf(got))
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("range_confirmed: arr[0x10] (index [16,16] >= 10) should be confirmed, got %q", c.SuspicionLevel)
	}
}
