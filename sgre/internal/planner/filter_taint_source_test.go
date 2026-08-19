//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// taintFixture exercises the taint-source filter: a path that receives
// user input (getenv) must be kept, a path that is provably a local literal
// must be suppressed, and a path that is a function parameter must be kept
// (the caller controls it).
const taintFixture = `#include <stdlib.h>
#include <stdio.h>

int tp_tainted_path(void) {
    char *path = getenv("HOME");
    FILE *f = fopen(path, "r");
    return f != 0;
}

int fp_safe_path(void) {
    char buf[64] = "/tmp/log.txt";
    FILE *f = fopen(buf, "r");
    return f != 0;
}

int param_path(char *path) {
    FILE *f = fopen(path, "r");
    return f != 0;
}
`

func hasTaintEvidence(c EvidenceItem) bool {
	for _, f := range c.Evidence {
		if f.Type == "taint_source" {
			return true
		}
	}
	return false
}

func TestTaintSourceFilter_PathTraversal(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "taint.c")
	if err := os.WriteFile(path, []byte(taintFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewPathTraversalDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "path-traversal")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	tp, ok := byFunc["tp_tainted_path"]
	if !ok {
		t.Errorf("expected tainted path tp_tainted_path to be kept, got %v", candidateNames(result))
	} else if !hasTaintEvidence(tp) {
		t.Errorf("expected tp_tainted_path to carry a taint_source evidence fragment, got %+v", tp.Evidence)
	}

	if _, ok := byFunc["fp_safe_path"]; ok {
		t.Errorf("expected safe literal path fp_safe_path to be suppressed, got %v", candidateNames(result))
	}

	if _, ok := byFunc["param_path"]; !ok {
		t.Errorf("expected parameter path param_path to be kept (caller-controlled), got %v", candidateNames(result))
	}
}

func TestTaintSourceFilter_Interprocedural(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "ipt.c")
	src := `#include <stdlib.h>
#include <stdio.h>

char *get_input(void) {
    return getenv("HOME");
}

char *get_safe(void) {
    return "/tmp/x";
}

int main(void) {
    char *p = get_input();
    FILE *f1 = fopen(p, "r");
    char *q = get_safe();
    FILE *f2 = fopen(q, "r");
    return f1 != 0 && f2 != 0;
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewPathTraversalDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "path-traversal")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	// p = get_input() where get_input returns getenv: inter-procedurally tainted,
	// so fopen(p) is kept with a taint_source fragment. q = get_safe() returns a
	// literal, so fopen(q) is suppressed.
	if len(result.Candidates) != 1 {
		t.Fatalf("expected exactly 1 candidate (tainted p), got %d: %v", len(result.Candidates), candidateNames(result))
	}
	if !hasTaintEvidence(result.Candidates[0]) {
		t.Errorf("expected the kept candidate to carry taint_source evidence, got %+v", result.Candidates[0].Evidence)
	}
	if len(result.Summary.Dropped) != 1 {
		t.Fatalf("expected 1 dropped candidate, got %d", len(result.Summary.Dropped))
	}
	if !strings.Contains(result.Summary.Dropped[0].Reason, "q") {
		t.Errorf("expected the dropped candidate to be q (get_safe literal), got reason %q", result.Summary.Dropped[0].Reason)
	}
}

func TestTaintSourceFilter_ParamTaintForward(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "pt.c")
	src := `#include <stdlib.h>

void run(char *c) {
    system(c);
}

void caller(void) {
    char *cmd = getenv("CMD");
    run(cmd);
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewInterprocBuilder(store, p, logger).Build(ctx)
	evidence.NewInjectionDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "injection")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	// The sink `system(c)` in run() is on a parameter; caller passes the tainted
	// `cmd` (getenv) into it, so the PARAM_BINDING forward edge must confirm it.
	found := false
	for _, c := range result.Candidates {
		if c.Target.Function == "run" {
			found = true
			if !hasTaintEvidence(c) {
				t.Errorf("expected param sink system(c) to be confirmed via PARAM_BINDING forward taint, got %+v", c.Evidence)
			}
		}
	}
	if !found {
		t.Errorf("expected a candidate in run(), got %v", candidateNames(result))
	}
}

func TestTaintSourceFilter_Injection(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "inj.c")
	src := `#include <stdlib.h>
void run_cmd(void) {
    char *cmd = getenv("CMD");
    system(cmd);
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewInjectionDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "injection")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	found := false
	for _, c := range result.Candidates {
		if c.Target.Variable == "cmd" {
			found = true
			if !hasTaintEvidence(c) {
				t.Errorf("expected injection candidate for cmd to carry a taint_source fragment, got %+v", c.Evidence)
			}
		}
	}
	if !found {
		t.Errorf("expected a tainted injection candidate for cmd, got %v", candidateNames(result))
	}
}

// TestTaintSourceFilter_ParamPassthrough locks in the context-sensitive return
// summary: a function that returns its parameter verbatim (char *id(char *s) {
// return s; }) is tainted iff that parameter is tainted. `id(getenv(...))`
// taints the result (gen), `id(x)` with a tainted x taints the result (copy),
// and `id("literal")` does not taint — the literal case stays suppressed.
func TestTaintSourceFilter_ParamPassthrough(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "passthrough.c")
	src := `#include <stdlib.h>
#include <stdio.h>

char *id(char *s) {
    return s;
}

int sink_direct(void) {
    char *p = id(getenv("CMD"));
    FILE *f = fopen(p, "r");
    return f != 0;
}

int sink_copy(void) {
    char *x = getenv("CMD");
    char *p = id(x);
    FILE *f = fopen(p, "r");
    return f != 0;
}

int sink_clean(void) {
    char *p = id("/tmp/x");
    FILE *f = fopen(p, "r");
    return f != 0;
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewPathTraversalDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "path-traversal")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	for _, fn := range []string{"sink_direct", "sink_copy"} {
		c, ok := byFunc[fn]
		if !ok {
			t.Errorf("expected %s (taint via param-passthrough) to be kept, got %v", fn, candidateNames(result))
			continue
		}
		if !hasTaintEvidence(c) {
			t.Errorf("expected %s to carry a taint_source evidence fragment, got %+v", fn, c.Evidence)
		}
	}

	if _, ok := byFunc["sink_clean"]; ok {
		t.Errorf("expected sink_clean (id of a literal) to be suppressed, got %v", candidateNames(result))
	}
}

// TestTaintSourceFilter_MultiLevelPassthrough locks in the transitive
// returnsParam fixpoint: wrap2(s) { return id(s); } returns taint iff its
// parameter is tainted (id is itself a passthrough). wrap2(getenv(...)) taints
// the result (gen), wrap2(x) with tainted x taints it (copy), and
// wrap2("literal") stays clean.
func TestTaintSourceFilter_MultiLevelPassthrough(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "passthrough2.c")
	src := `#include <stdlib.h>
#include <stdio.h>

char *id(char *s) {
    return s;
}

char *wrap2(char *s) {
    return id(s);
}

int sink_direct(void) {
    char *p = wrap2(getenv("CMD"));
    FILE *f = fopen(p, "r");
    return f != 0;
}

int sink_copy(void) {
    char *x = getenv("CMD");
    char *p = wrap2(x);
    FILE *f = fopen(p, "r");
    return f != 0;
}

int sink_clean(void) {
    char *p = wrap2("/tmp/x");
    FILE *f = fopen(p, "r");
    return f != 0;
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewPathTraversalDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "path-traversal")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	for _, fn := range []string{"sink_direct", "sink_copy"} {
		c, ok := byFunc[fn]
		if !ok {
			t.Errorf("expected %s (taint via multi-level passthrough) to be kept, got %v", fn, candidateNames(result))
			continue
		}
		if !hasTaintEvidence(c) {
			t.Errorf("expected %s to carry a taint_source evidence fragment, got %+v", fn, c.Evidence)
		}
	}
	if _, ok := byFunc["sink_clean"]; ok {
		t.Errorf("expected sink_clean (wrap2 of a literal) to be suppressed, got %v", candidateNames(result))
	}
}
