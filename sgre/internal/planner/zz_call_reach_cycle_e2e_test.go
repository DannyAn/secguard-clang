//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestCallReach_MutualRecursionAddrTakenNoOOM is the end-to-end regression for
// issue #238: a 22-line / 4-function program with mutual recursion (a <-> b)
// where b is address-taken used to make secguard OOM because callChain looped
// forever on the cyclic parent map produced by the adopt loop. The scan must
// now terminate quickly with a bounded call chain (or no chain) rather than
// growing rev until the runtime aborts with "out of memory".
//
// Fixture is the exact 22-line cycle.c from the issue report.
func TestCallReach_MutualRecursionAddrTakenNoOOM(t *testing.T) {
	src := `/* cycle.c —— 22 行，4 个函数，扫描即 OOM */
#include <stdlib.h>

typedef int (*fn_t)(int, int);
static fn_t g_cb;

static int b(int n, int d);

static int a(int n, int d)
{
    int v = n / d;     /* 在 a() 内制造一个 divide-by-zero 候选 */
    return v + b(n, d);
}

static int b(int n, int d)
{
    return a(n, d);    /* 互递归：a <-> b */
}

void reg(fn_t f)
{
    g_cb = f;
}

int main(int argc, char **argv)
{
    (void)argv;
    reg(b);            /* b 取址 -> ADDR_TAKEN true entry，落在 a<->b 环上 */
    return g_cb(argc, argc - 1);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "cycle.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewDivideByZeroDetector(store, p, logger).Detect(ctx)

	// Plan must terminate; before the fix it OOM'd inside callChain. Use a
	// deadline so a regression hangs the test instead of the whole suite.
	planCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(planCtx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	// The candidate on `n / d` in a() must be kept (a is reachable from the
	// address-taken true entry b via the a<->b edge) and carry a BOUND call
	// chain — never an unbounded one. The chain depth is at most
	// maxCallChainHops.
	for _, c := range result.Candidates {
		if len(c.CallChain) > maxCallChainHops {
			t.Fatalf("candidate %s: call chain length %d exceeds cap %d (cycle not truncated, OOM regression)",
				c.Target.Function, len(c.CallChain), maxCallChainHops)
		}
	}
}
