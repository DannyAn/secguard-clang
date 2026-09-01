//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// planNullDerefMacroFiles runs the full null-deref pipeline on a set of inline
// files. It is the multi-file analogue of planNullDerefMacro, for testing
// cross-file macro visibility (macro defined in a .h header, called in a .c
// source).
func planNullDerefMacroFiles(t *testing.T, files map[string]string) *PlanResult {
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
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

const iterMacroHeader = `#ifndef ITER_MACRO_H
#define ITER_MACRO_H
#include <stdlib.h>

typedef struct sample_node {
    struct sample_node *next;
    int car;
} sample_node_t;

typedef struct sample_list {
    sample_node_t *head;
} sample_list_t;

static inline sample_node_t *SAMPLE_First(sample_list_t *lst) {
    return lst ? lst->head : NULL;
}
static inline sample_node_t *SAMPLE_Next(sample_node_t *node) {
    return node ? node->next : NULL;
}

#define SAMPLE_Scan(pList, pNode, TypeCast) \
    for ((pNode) = (TypeCast)SAMPLE_First((pList)); \
         (pNode) != NULL; \
         (pNode) = (TypeCast)SAMPLE_Next((pNode)))
#endif
`

const iterMacroUsageSrc = `#include "iter_macro.h"

int scan_and_process(sample_list_t *sll) {
    sample_node_t *policy = NULL;
    SAMPLE_Scan(sll, policy, sample_node_t *) {
        if (policy->car == 0) {
            return 1;
        }
    }
    return 0;
}

int real_bug(sample_list_t *sll) {
    sample_node_t *policy = NULL;
    if (policy->car == 0) {
        return 1;
    }
    return 0;
}
`

// TestNullDeref_IterMacroCrossFile: SAMPLE_Scan is defined in iter_macro.h and
// called from iter_usage.c. The macro's for-init writes `policy` (arg index 1)
// and the loop condition null-guards it, so policy is non-null inside the loop
// body. The per-file macro analysis of the .c file cannot see the .h definition,
// so the cross-file merged macro write-summary is needed to kill policy's null
// source at the call site.
func TestNullDeref_IterMacroCrossFile(t *testing.T) {
	result := planNullDerefMacroFiles(t, map[string]string{
		"iter_macro.h":  iterMacroHeader,
		"iter_usage.c":  iterMacroUsageSrc,
	})
	if c := candidateForFunc(t, result, "scan_and_process"); c != nil {
		t.Errorf("scan_and_process should NOT be flagged (policy is written by SAMPLE_Scan for-init and null-guarded by the loop condition), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if c := candidateForFunc(t, result, "real_bug"); c == nil {
		t.Errorf("real_bug must be flagged (policy is NULL and dereferenced without the macro), got: %s", candidateNames(result))
	}
}

// TestNullDeref_IterMacroConfigDeclared: SAMPLE_Scan is NOT defined anywhere in
// the scan tree (simulating an SDK header outside the indexed tree). The user
// declares it in secguard.toml [iterator_macros.macros] with iterator arg index
// 1. The config-declared iterator macro kill suppresses the false positive.
func TestNullDeref_IterMacroConfigDeclared(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "secguard.toml")
	tomlContent := `[iterator_macros.macros]
SAMPLE_Scan = [1]
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(tomlPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

	src := `#include <stdlib.h>

typedef struct sample_node {
    struct sample_node *next;
    int car;
} sample_node_t;

typedef struct sample_list {
    sample_node_t *head;
} sample_list_t;

int scan_and_process(sample_list_t *sll) {
    sample_node_t *policy = NULL;
    SAMPLE_Scan(sll, policy, sample_node_t *) {
        if (policy->car == 0) {
            return 1;
        }
    }
    return 0;
}

int real_bug(sample_list_t *sll) {
    sample_node_t *policy = NULL;
    if (policy->car == 0) {
        return 1;
    }
    return 0;
}
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "scan_and_process"); c != nil {
		t.Errorf("scan_and_process should NOT be flagged (config declares SAMPLE_Scan as iterator macro with arg 1), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if c := candidateForFunc(t, result, "real_bug"); c == nil {
		t.Errorf("real_bug must be flagged (policy is NULL and dereferenced without the macro), got: %s", candidateNames(result))
	}
}