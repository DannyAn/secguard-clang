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

// planNullDerefGuardMacro runs the null-deref pipeline (index → graph →
// detectors → planner) on an inline source, including the null-guard detector,
// which the guard-macro fix lives in.
func planNullDerefGuardMacro(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "guard_macro.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// A guard macro (`#define CHECK_RET(cond, ret) if ((cond)) return ret;`) null-checks
// its argument and returns on the null branch, so the variable is non-null after
// the call. A null-seeded variable must not be reported as a null-deref at a use
// after the guard macro. Reduced to generic shapes (the vendor-specific guard
// macros are intentionally not reproduced).
const guardMacroPreamble = `#include <stdlib.h>

typedef struct vsys { int *head; } vsys_t;

vsys_t *lookup_vsys(int idx) { return NULL; }

#define CHECK_RET(cond, ret) \
    if ((cond)) { return ret; }

#define CHECK_RET_NOT(ptr, ret) \
    if (!(ptr)) { return ret; }

#define OK 0
`

func TestNullDeref_GuardMacroNotNull(t *testing.T) {
	src := guardMacroPreamble + `
int scan_vsys(int idx) {
    vsys_t *ctrl = lookup_vsys(idx);
    CHECK_RET((ctrl == NULL), OK);
    for (int *p = ctrl->head; p != NULL; p = p) {
        *p = 1;
    }
    return 0;
}

int scan_vsys_not(int idx) {
    vsys_t *ctrl = lookup_vsys(idx);
    CHECK_RET_NOT(ctrl, OK);
    for (int *p = ctrl->head; p != NULL; p = p) {
        *p = 1;
    }
    return 0;
}
`
	result := planNullDerefGuardMacro(t, src)
	if c := candidateForFunc(t, result, "scan_vsys"); c != nil {
		t.Errorf("scan_vsys should NOT be flagged (ctrl null-guarded by CHECK_RET), got var=%s", c.Target.Variable)
	}
	if c := candidateForFunc(t, result, "scan_vsys_not"); c != nil {
		t.Errorf("scan_vsys_not should NOT be flagged (ctrl null-guarded by CHECK_RET_NOT), got var=%s", c.Target.Variable)
	}
}
