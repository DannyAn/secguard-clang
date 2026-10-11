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

// TestUninit_AddressTakenFieldNotConfirmed pins the output-param/decay downgrade:
// a struct field written through `&field` (the nlog HTONBUF accessor pattern) is
// invisible to the flow model, so the later field read must stay suspected — not
// auto-confirmed — because hasOutputParamWrite sees the address-of lvalue.
func TestUninit_AddressTakenFieldNotConfirmed(t *testing.T) {
	store := runUninitFixture(t, `typedef struct { unsigned int hpfS6Addr32[4]; } ip6_t;
static ip6_t g_src;
unsigned int HTONBUF(unsigned int *dst, unsigned int src);
int use_ipv6(void) {
    ip6_t ipv6;
    HTONBUF(&ipv6.hpfS6Addr32[0], g_src.hpfS6Addr32[0]);
    return (int)ipv6.hpfS6Addr32[0];
}
`)
	for _, c := range store {
		if c.Target.Function == "use_ipv6" {
			if c.SuspicionLevel == "confirmed" {
				t.Errorf("use_ipv6: HTONBUF(&ipv6.hpfS6Addr32[0]) writes the field, the read must not be auto-confirmed, got %q", c.SuspicionLevel)
			}
		}
	}
}

// TestUninit_UnrelatedMacroStillConfirmed pins the precision of the downgrade: an
// unrelated ALL_CAPS macro on the same line as a genuinely-uninitialized read
// must NOT downgrade it — the read stays confirmed (nothing writes the variable).
// This is the regression for the former ±8-line macro window, which downgraded
// `a` in `return a + 1 + MYMACRO(0);` even though MYMACRO(0) never writes a.
func TestUninit_UnrelatedMacroStillConfirmed(t *testing.T) {
	store := runUninitFixture(t, `#define MYMACRO(x) (x)
int f(void) {
    int a;
    return a + 1 + MYMACRO(0);
}
`)
	found := false
	for _, c := range store {
		if c.Target.Function == "f" && c.Target.Variable == "a" {
			found = true
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("f: nothing writes a, so the uninitialized read must be auto-confirmed, got %q", c.SuspicionLevel)
			}
		}
	}
	if !found {
		t.Fatal("expected a candidate for the uninitialized read of a, got none")
	}
}

func runUninitFixture(t *testing.T, src string) []EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "uninit.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result.Candidates
}
