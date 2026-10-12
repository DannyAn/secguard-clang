//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func planUnsignedSub(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "usub.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewIntegerOverflowDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "integer-overflow")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// An entry-return guard `if (consumed > total) return;` proves the subtraction
// safe on the fall-through path and must be suppressed by UnsignedSubGuardFilter.
func TestUnsignedSubGuard_EntryGuardSuppressed(t *testing.T) {
	src := `#include <stdint.h>
void use(uint32_t v);
void entry_guard(uint32_t total, uint32_t consumed) {
    if (consumed > total) return;
    use(total - consumed);
}
`
	has := candidateFuncs(t, planUnsignedSub(t, src))
	if has["entry_guard"] {
		t.Errorf("entry_guard (consumed > total return; then total - consumed) should be suppressed, got %v", has)
	}
}

// No guard at all: the survivor must carry `guard@none`, and its operand
// provenance must mark the subtrahend as an externally-supplied parameter
// (`rhs@param` + `rhs-influenced`) — the two facts that let the classifier
// judge the subtraction from the _index row alone.
func TestUnsignedSubGuard_UnguardedCarriesGuardNoneHint(t *testing.T) {
	src := `#include <stdint.h>
void use(uint32_t v);
void unguarded(uint32_t total, uint32_t consumed) {
    use(total - consumed);
}
`
	result := planUnsignedSub(t, src)
	c := candidateForFunc(t, result, "unguarded")
	if c == nil {
		t.Fatalf("unguarded should be kept, got %v", candidateNames(result))
	}
	for _, want := range []string{"guard@none", "rhs@param", "rhs-influenced", "sink@call_arg"} {
		if !containsWord(c.Hint, want) {
			t.Errorf("unguarded hint = %q, want it to contain %q", c.Hint, want)
		}
	}
}

// An accumulator reassigned after the guard invalidates the bound, so the
// candidate must NOT be suppressed (and must not be falsely dismissed). Its
// subtrahend is a local accumulator (`rhs@local`), not an external parameter.
func TestUnsignedSubGuard_ReassignedAfterGuardKept(t *testing.T) {
	src := `#include <stdint.h>
uint32_t grow(uint32_t n);
void use(uint32_t v);
void accumulator(uint32_t buf_len) {
    uint32_t length = 0;
    if (length > buf_len) return;  // trivial at 0, does not protect later growth
    length += grow(1);
    use(buf_len - length);
}
`
	result := planUnsignedSub(t, src)
	c := candidateForFunc(t, result, "accumulator")
	if c == nil {
		t.Fatalf("accumulator (length reassigned after guard) should be kept, got %v", candidateNames(result))
	}
	if !containsWord(c.Hint, "rhs@local") {
		t.Errorf("accumulator hint = %q, want subtrahend classified rhs@local", c.Hint)
	}
}

func containsWord(s, word string) bool {
	for _, f := range strings.Fields(s) {
		if f == word {
			return true
		}
	}
	return false
}
