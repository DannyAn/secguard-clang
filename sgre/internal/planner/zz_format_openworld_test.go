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

// Issue #253 P2-1: a non-static format wrapper whose only taint basis is the
// open-world assumption ("an external caller may pass a tainted fmt") must NOT
// be auto-confirmed when the sink is a LOCAL copy of the parameter (the flow
// path). The open-world assumption is a fail-open hypothesis, not a machine
// proof, so the candidate stays suspected for the AI.
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
	var wrapper *EvidenceItem
	for i := range result.Candidates {
		if result.Candidates[i].Target.Function == "log_wrapper" {
			wrapper = &result.Candidates[i]
		}
	}
	if wrapper == nil {
		t.Fatalf("log_wrapper must stay a suspected candidate (the assertion would be vacuous otherwise), got %v", candidateNames(result))
	}
	if wrapper.SuspicionLevel == "confirmed" {
		t.Errorf("an open-world entry assumption (no real caller taint witness) must not auto-confirm the format wrapper (variable=%s)", wrapper.Target.Variable)
	}
}
