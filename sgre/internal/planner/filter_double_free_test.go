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

// dfFixture exercises the freed-state double-free filter: a genuine double-free
// (free then free with no intervening reassignment) must be kept and marked
// confirmed, while a free/reassign/free pattern (the second free targets a
// different block) must be suppressed.
const dfFixture = `#include <stdlib.h>

int tp_double_free(void) {
    char *p = (char *)malloc(16);
    free(p);
    free(p);
    return 0;
}

int fp_reassign_between(void) {
    char *p = (char *)malloc(16);
    free(p);
    p = (char *)malloc(32);
    free(p);
    return 0;
}
`

func TestDoubleFreeFilter_Reassignment(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "df.c")
	if err := os.WriteFile(path, []byte(dfFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewDoubleFreeDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "double-free")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if !kept["tp_double_free"] {
		t.Errorf("expected genuine double-free tp_double_free to be kept, got %v", candidateNames(result))
	}
	if kept["fp_reassign_between"] {
		t.Errorf("expected fp_reassign_between (free then reassign then free) to be suppressed, got %v", candidateNames(result))
	}

	for _, c := range result.Candidates {
		if c.Target.Function == "tp_double_free" && c.SuspicionLevel != "confirmed" {
			t.Errorf("expected genuine double-free to be confirmed, got %q", c.SuspicionLevel)
		}
	}
}

// dfExclusiveFixture covers the mutually-exclusive-free shape: the first free is
// guarded and returns, the second is the tail free — the two never execute on the
// same path, so they must NOT be reported as a double-free.
const dfExclusiveFixture = `#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

bool guarded_free(const char *cmd) {
    char *cmd_tmp = strdup(cmd);
    char *tmp_ptr = NULL;
    char *cmd_part = strtok_r(cmd_tmp, " ", &tmp_ptr);
    if (cmd_part != NULL) {
        cmd_part = strtok_r(NULL, " ", &tmp_ptr);
        if (strlen(cmd_part) >= 10) {
            free(cmd_tmp);
            return true;
        }
    }
    free(cmd_tmp);
    return false;
}

int tp_sequential_free(void) {
    char *p = (char *)malloc(16);
    free(p);
    free(p);
    return 0;
}
`

func TestDoubleFreeFilter_MutuallyExclusiveFrees(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "df_excl.c")
	if err := os.WriteFile(path, []byte(dfExclusiveFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewDoubleFreeDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "double-free")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	kept := map[string]bool{}
	for _, c := range result.Candidates {
		kept[c.Target.Function] = true
	}

	if kept["guarded_free"] {
		t.Errorf("guarded_free (mutually-exclusive frees) must be suppressed, got %v", candidateNames(result))
	}
	if !kept["tp_sequential_free"] {
		t.Errorf("tp_sequential_free (sequential double-free) must be kept, got %v", candidateNames(result))
	}
}
