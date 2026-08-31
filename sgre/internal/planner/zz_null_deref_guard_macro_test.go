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

// TestNullDeref_MixedConditionGuard: a multi-condition early-return guard
// (`if (a == NULL || b == NULL) return;`) establishes BOTH a and b as non-null.
// Only the first operand used to be recognized, so a later deref of the second
// operand (b) was misreported.
func TestNullDeref_MixedConditionGuard(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct sect { int *ip; } sect_t;
typedef struct pool { int user_car_num; } pool_t;

sect_t *find_sect(int id) { return NULL; }
pool_t *get_pool_key(void *g) { return NULL; }
void release(void *g) {}

#define ERR -1

int set_used(int id) {
    void *group = malloc(1);
    pool_t *carnat_pool = get_pool_key(group);
    sect_t *sect = find_sect(id);
    if (sect == NULL || carnat_pool == NULL) {
        release(group);
        return ERR;
    }
    int user_num = 0;
    while (user_num < carnat_pool->user_car_num) {
        user_num++;
    }
    return 0;
}
`
	result := planNullDerefGuardMacro(t, src)
	if c := candidateForFunc(t, result, "set_used"); c != nil {
		t.Errorf("set_used should NOT be flagged (carnat_pool is null-guarded in the mixed condition), got var=%s", c.Target.Variable)
	}
}

// TestNullDeref_GuardMacroIteratorDeref pins the guard-macro fix against the
// iterator-initializer deref shape (`TAILQ_FIRST(&(ctrl->field))`): the deref is
// nested inside an address-of passed to another macro, but it is still a read of
// ctrl and must be suppressed by the preceding `CHECK_RET((ctrl == NULL), ret)`
// guard.
func TestNullDeref_GuardMacroIteratorDeref(t *testing.T) {
	src := guardMacroPreamble + `
typedef struct pnode { struct pnode *link; } pnode_t;

#define TAILQ_FIRST(head) ((pnode_t *)0)
#define TAILQ_NEXT(node, link) ((pnode_t *)0)

int scan_vsys_head(int idx) {
    vsys_t *ctrl = lookup_vsys(idx);
    CHECK_RET((ctrl == NULL), OK);
    pnode_t *group_node;
    for (group_node = TAILQ_FIRST(&(ctrl->head)); group_node != NULL;
         group_node = TAILQ_NEXT(group_node, link)) {
        ;
    }
    return 0;
}
`
	result := planNullDerefGuardMacro(t, src)
	if c := candidateForFunc(t, result, "scan_vsys_head"); c != nil {
		t.Errorf("scan_vsys_head should NOT be flagged (ctrl is null-guarded by CHECK_RET before the iterator deref), got var=%s", c.Target.Variable)
	}
}
