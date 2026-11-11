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

// Issue #261 item 5: a logging wrapper that FORWARDS its own format parameter
// (`log_impl(level, fmt, ap)` → `vsprintf_s(buf, n, fmt, ap)`, reached through
// `log_info(fmt, ...)` → `log_impl(..., fmt, ap)`) must be dropped when every
// in-tree final caller passes a string literal. The open-world param-taint
// promotion marks the wrapper "confirmed", but the constant-path proof proves
// the forwarded parameter is never attacker-controlled and dismisses it.
func TestFormatString_ForwardingWrapperAllLiteralCallersDropped(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	src := `#include <stdio.h>
#include <stdarg.h>

void log_impl(int level, const char *fmt, va_list ap)
{
    char buf[2048];
    vsprintf_s(buf, sizeof(buf), fmt, ap);
}

void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_impl(1, fmt, ap);
    va_end(ap);
}

void caller(void)
{
    log_info("fd %d purpose %d", 3, 5);
    log_info("send ok.");
}
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
		if result.Candidates[i].Target.Function == "log_impl" {
			t.Fatalf("log_impl must be dropped when every final caller passes a literal, got: %+v", result.Candidates[i])
		}
	}
}

// Negative control: one final caller passes a VARIABLE format, so the forwarded
// parameter is not provably constant and the wrapper must stay a candidate.
func TestFormatString_ForwardingWrapperVariableCallerKept(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	src := `#include <stdio.h>
#include <stdarg.h>

void log_impl(int level, const char *fmt, va_list ap)
{
    char buf[2048];
    vsprintf_s(buf, sizeof(buf), fmt, ap);
}

void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_impl(1, fmt, ap);
    va_end(ap);
}

void caller(const char *user_fmt)
{
    log_info(user_fmt, 3);
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "fmtwrap2.c")
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
	found := false
	for i := range result.Candidates {
		if result.Candidates[i].Target.Function == "log_impl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("log_impl must stay a candidate when a caller passes a variable format, got %v", candidateNames(result))
	}
}
