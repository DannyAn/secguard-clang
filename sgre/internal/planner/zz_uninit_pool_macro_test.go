//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func planUninitMacroFiles(t *testing.T, files map[string]string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	dir := t.TempDir()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(files[name]), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	idx := indexer.NewIndexer(store, logger)
	for _, name := range names {
		if _, err := idx.Index(ctx, filepath.Join(dir, name)); err != nil {
			t.Fatalf("index %s: %v", name, err)
		}
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx)
	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

const poolLoopHeader = `#ifndef POOL_LOOP_H
#define POOL_LOOP_H
#include <stdint.h>

typedef struct { uint16_t next; uint16_t is_ipv6; } pool_group_t;
typedef struct { uint16_t id; const char *ip_type; } pool_web_param_t;

#define POOL_ID_INVALID 0xFFFF

static inline pool_group_t *POOL_GROUP(uint16_t pool_id) {
    extern pool_group_t g_pool_var_groups[];
    return &g_pool_var_groups[pool_id];
}
static inline uint16_t pool_next_group(uint16_t pool_id) {
    return POOL_GROUP(pool_id)->next;
}
extern uint16_t pool_first_group(uint16_t id);

#define POOL_FOR(id, pool_id)                                            \
    for ((pool_id) = pool_first_group(id); POOL_ID_INVALID != (pool_id); \
         (pool_id) = pool_next_group((pool_id)))
#endif
`

const poolUsageSrc = `#include <string.h>
#include "pool_loop.h"

void *pool_fill_data(const pool_web_param_t *param, uint32_t match_cnt, uint32_t start_line, uint32_t end_line) {
    void *data = (void *)1;
    uint16_t pool_id;
    uint32_t count = 0;
    POOL_FOR(param->id, pool_id) {
        if (match_cnt == 0) { break; }
        if (count >= end_line) { break; }
        pool_group_t *group = POOL_GROUP(pool_id);
        char *ip_type = group->is_ipv6 ? "v6" : "v4";
        if ((strcmp(param->ip_type, "all") != 0) && (strcmp(param->ip_type, ip_type) != 0)) {
            continue;
        }
        count++;
    }
    return data;
}

int real_uninit_bug(void) {
    uint16_t pool_id;
    return (int)pool_id;
}
`

// TestUninit_PoolForMacroCrossFile: POOL_FOR is defined in a .h header and called
// from a .c source. The macro's init clause writes pool_id, but the per-file macro
// analysis of the .c file cannot see the definition, so pool_id was misreported as
// uninitialized at the POOL_FOR call site and at POOL_GROUP(pool_id). The cross-file
// merged macro write-summary makes the macro visible at the call site.
func TestUninit_PoolForMacroCrossFile(t *testing.T) {
	result := planUninitMacroFiles(t, map[string]string{"pool_loop.h": poolLoopHeader, "pool_usage.c": poolUsageSrc})
	if c := candidateForFunc(t, result, "pool_fill_data"); c != nil {
		t.Errorf("pool_fill_data should NOT be flagged (pool_id is initialized by POOL_FOR macro init clause), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	// real_uninit_bug has no POOL_FOR call, so pool_id is genuinely uninitialized.
	if c := candidateForFunc(t, result, "real_uninit_bug"); c == nil {
		t.Errorf("real_uninit_bug must be flagged (pool_id is never initialized), got: %s", candidateNames(result))
	}
}