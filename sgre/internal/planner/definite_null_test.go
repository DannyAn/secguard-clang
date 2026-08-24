//go:build !nosqlite

package planner

import (
	"context"
	"io"
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

// TestDefiniteNull_MustAnalysis pins the must-null tier: `p = NULL` (an explicit
// null assignment) reaching a dereference is a CERTAIN null-deref, distinct from
// `p = malloc()` which is only a possible null. The former carries
// has_definite_null=true and must survive the pipeline.
func TestDefiniteNull_MustAnalysis(t *testing.T) {
	src := `#include <stdlib.h>

int certain_null_deref(void) {
    int *p = NULL;
    return *p;
}

int possible_null_deref(void) {
    int *q = malloc(sizeof(int));
    return *q;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "dn.c")
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
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	byFunc := map[string]bool{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = true
		if c.Target.Function == "certain_null_deref" {
			if !c.HasDefiniteNull {
				t.Errorf("certain_null_deref must carry has_definite_null=true")
			}
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("certain_null_deref (definite null) must be confirmed, got %q", c.SuspicionLevel)
			}
		}
		if c.Target.Function == "possible_null_deref" {
			if c.HasDefiniteNull {
				t.Errorf("possible_null_deref must NOT carry has_definite_null (it is only possibly-null)")
			}
			if c.SuspicionLevel != "suspected" {
				t.Errorf("possible_null_deref (possible null) must be suspected, got %q", c.SuspicionLevel)
			}
		}
	}
	if !byFunc["certain_null_deref"] {
		t.Errorf("certain_null_deref should be a finding, got %v", byFunc)
	}
}
