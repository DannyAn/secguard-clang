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

// Issue #253 P2-1 + issue #261 item 5: a non-static format wrapper whose sink
// is a LOCAL copy of the parameter (`local = fmt`) is now dropped when every
// in-tree caller passes a compile-time literal — the constant-path proof
// resolves the local copy to the parameter and proves the parameter is never
// attacker-controlled. The open-world promotion alone is not a machine proof,
// but a positive all-literal-caller proof IS, so the candidate is dismissed
// rather than handed to the AI as suspected.
func TestTaintSourceFilter_OpenWorldEntryDoesNotConfirm(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	src := `#include <stdio.h>
#include <stdarg.h>

void log_wrapper(const char *fmt, ...)
{
    const char *local = fmt;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsprintf_s(buf, sizeof(buf), local, ap);
    va_end(ap);
}

void caller(void) { log_wrapper("%s", "x"); }
`
	dir := t.TempDir()
	path := filepath.Join(dir, "fmtwrap.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewFormatStringDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "format-string")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for i := range result.Candidates {
		if result.Candidates[i].Target.Function == "log_wrapper" {
			t.Fatalf("log_wrapper must be dropped when its local copy resolves to an all-literal parameter, got %+v", result.Candidates[i])
		}
	}
}
