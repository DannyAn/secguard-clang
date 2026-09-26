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

// planType runs the full pipeline for one vuln type and returns the converged
// candidates keyed by function name.
func planType(t *testing.T, src, vulnType string) map[string]EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "u.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)
	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, vulnType)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	out := map[string]EvidenceItem{}
	for _, c := range res.Candidates {
		out[c.Target.Function] = c
	}
	return out
}

// Cast-wrapped release arguments must be recognized across the memory detectors:
// free((void*)p), free((void*)p) twice, and close((int)fd) — the previous
// identifier-only matching missed the cast_expression spelling.
func TestCrossCut_CastReleaseArgs(t *testing.T) {
	src := `#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
int uaf_cast(void) {
    int *p = malloc(8);
    free((void *)p);
    return *p;
}
int df_cast(void) {
    int *p = malloc(8);
    free(p);
    free((void *)p);
    return 0;
}
int rl_cast_release(void) {
    int fd = open("/tmp/x", 0);
    close((int)fd);
    return 0;
}
`
	if got := planType(t, src, "use-after-free"); got["uaf_cast"].Target.Function == "" {
		t.Errorf("uaf_cast: free((void*)p) then *p must be a use-after-free, got none")
	}
	if got := planType(t, src, "double-free"); got["df_cast"].Target.Function == "" {
		t.Errorf("df_cast: free(p) then free((void*)p) must be a double-free, got none")
	}
	if got := planType(t, src, "resource-leak"); got["rl_cast_release"].Target.Function != "" {
		t.Errorf("rl_cast_release: close((int)fd) releases fd, must not leak")
	}
}

// positiveGuardOn must compare the operand exactly: `if (nfd >= 0) close(fd)` does
// NOT guard fd (the previous strings.Contains matched the "fd >=" in "nfd >="),
// so fd leaks on the nfd < 0 path.
func TestCrossCut_PositiveGuardWordBoundary(t *testing.T) {
	src := `#include <fcntl.h>
#include <unistd.h>
int guard_substr(int nfd) {
    int fd = open("/tmp/x", 0);
    if (nfd >= 0) close(fd);
    return 0;
}
int guard_exact(int fd) {
    if (fd >= 0) close(fd);
    return 0;
}
`
	got := planType(t, src, "resource-leak")
	if got["guard_substr"].Target.Function == "" {
		t.Errorf("guard_substr: close(fd) guarded by nfd (not fd) still leaks fd on the nfd<0 path, got none")
	}
	if got["guard_exact"].Target.Function != "" {
		t.Errorf("guard_exact: close(fd) guarded by fd >= 0 must not leak, got %q", got["guard_exact"].Target.Function)
	}
}
