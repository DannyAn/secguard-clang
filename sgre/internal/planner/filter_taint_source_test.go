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

int cast_literal_path(void) {
    FILE *f = fopen((const char *)"/tmp/cast.txt", "r");
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

	if _, ok := byFunc["cast_literal_path"]; ok {
		t.Errorf("expected cast-wrapped literal path cast_literal_path to be suppressed, got %v", candidateNames(result))
	}

	if _, ok := byFunc["param_path"]; !ok {
		t.Errorf("expected parameter path param_path to be kept (caller-controlled), got %v", candidateNames(result))
	}
}

func TestTaintSourceFilter_StaticParamDropped(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "sp.c")
	src := `#include <stdlib.h>
#include <stdio.h>

static int read_cfg(const char *path) {
    FILE *f = fopen(path, "r");
    return f != 0;
}

static int read_user(const char *path) {
    FILE *f = fopen(path, "r");
    return f != 0;
}

int public_api(const char *path) {
    FILE *f = fopen(path, "r");
    return f != 0;
}

int public_api_nonconst(char *path) {
    FILE *f = fopen(path, "r");
    return f != 0;
}

int main(void) {
    int a = read_cfg("/etc/config");      /* constant caller -> static -> dropped */
    int b = read_user(getenv("HOME"));    /* tainted caller -> confirmed */
    int c = public_api("x");              /* non-static -> kept (external caller may taint) */
    int d = public_api_nonconst("y");     /* non-static -> kept (external caller may taint) */
    return a + b + c + d;
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

	if _, ok := byFunc["read_cfg"]; ok {
		t.Errorf("static read_cfg called with a constant should be dropped, got %v", candidateNames(result))
	}
	ru, ok := byFunc["read_user"]
	if !ok {
		t.Errorf("static read_user called with getenv should be confirmed (kept), got %v", candidateNames(result))
	} else if !hasTaintEvidence(ru) {
		t.Errorf("read_user should carry taint_source evidence, got %+v", ru.Evidence)
	}
	if _, ok := byFunc["public_api"]; !ok {
		t.Errorf("public_api (const char* param, non-static) should be kept (external caller may taint), got %v", candidateNames(result))
	}
	if _, ok := byFunc["public_api_nonconst"]; !ok {
		t.Errorf("public_api_nonconst (non-const param, non-static) should be kept (external caller may taint), got %v", candidateNames(result))
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

// TestTaintSourceFilter_NonSQLPublicParamKept locks in the scoping of the
// SQL-injection call-site const / const char* dismissals: those heuristics must
// NOT drop a non-static function's parameter sink for command-injection or
// format-string, where `const char *cmd` / `const char *fmt` is the canonical
// *vulnerable* declaration (an external caller may supply attacker input).
func TestTaintSourceFilter_NonSQLPublicParamKept(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "nonsql.c")
	src := `#include <stdlib.h>
#include <stdio.h>

void run_cmd(const char *cmd) {
    system(cmd);
}

void log_msg(const char *fmt) {
    printf(fmt);
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

	pl := NewPlanner(store, p, logger)

	// command injection: const char *cmd param of a non-static function must be
	// kept (an external caller may pass attacker-controlled input).
	evidence.NewInjectionDetector(store, p, logger).Detect(ctx)
	result, err := pl.Plan(ctx, "injection")
	if err != nil {
		t.Fatalf("plan injection: %v", err)
	}
	found := false
	for _, c := range result.Candidates {
		if c.Target.Function == "run_cmd" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("run_cmd (const char* cmd param, non-static) should be kept, got %v", candidateNames(result))
	}

	// format string: const char *fmt param of a non-static function must be kept.
	evidence.NewFormatStringDetector(store, p, logger).Detect(ctx)
	result, err = pl.Plan(ctx, "format-string")
	if err != nil {
		t.Fatalf("plan format-string: %v", err)
	}
	found = false
	for _, c := range result.Candidates {
		if c.Target.Function == "log_msg" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("log_msg (const char* fmt param, non-static) should be kept, got %v", candidateNames(result))
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

// TestTaintSourceFilter_ParamTaintIntoLocal locks in the entry-seeding fix: a
// sink on a LOCAL variable derived from a tainted parameter must be kept. The
// caller-influenced parameter is seeded into the callee's entry, so `cmd = s`
// (copy) and `cmd = build_cmd(s)` (passthrough) both propagate the taint to a
// local sink — previously a false negative.
func TestTaintSourceFilter_ParamTaintIntoLocal(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "paramlocal.c")
	src := `#include <stdlib.h>

char *build_cmd(char *s) {
    return s;
}

void sink_local_direct(char *s) {
    char *cmd = s;
    system(cmd);
}

void sink_local_passthrough(char *s) {
    char *cmd = build_cmd(s);
    system(cmd);
}

void caller(void) {
    char *input = getenv("CMD");
    sink_local_direct(input);
    sink_local_passthrough(input);
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

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	for _, fn := range []string{"sink_local_direct", "sink_local_passthrough"} {
		c, ok := byFunc[fn]
		if !ok {
			t.Errorf("expected %s (local sink from tainted param) to be kept, got %v", fn, candidateNames(result))
			continue
		}
		if !hasTaintEvidence(c) {
			t.Errorf("expected %s to carry a taint_source evidence fragment, got %+v", fn, c.Evidence)
		}
	}
}

// TestTaintSourceFilter_TransitiveParamTaint locks in the fixpoint: a
// param→param chain across multiple call hops (main → A → B → C) must propagate
// taint to the final sink, which the previous single forward pass missed.
func TestTaintSourceFilter_TransitiveParamTaint(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "transitive.c")
	src := `#include <stdlib.h>

void C(char *s) {
    char *cmd = s;
    system(cmd);
}

void B(char *s) {
    C(s);
}

void A(char *s) {
    B(s);
}

void main(void) {
    char *input = getenv("CMD");
    A(input);
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

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	c, ok := byFunc["C"]
	if !ok {
		t.Fatalf("expected C (transitive param taint main→A→B→C) to be kept, got %v", candidateNames(result))
	}
	if !hasTaintEvidence(c) {
		t.Errorf("expected C to carry a taint_source evidence fragment, got %+v", c.Evidence)
	}
}

// TestTaintSourceFilter_CopyFunctions locks in taint propagation through string/
// memory copy calls: the plain forms (strcpy/strcat/memcpy) and the bounds-
// checked Annex-K `_s` forms (strcpy_s), plus strdup's return-value passthrough.
// A copy whose source is a taint source (or a tainted variable) taints the
// destination; a copy from a literal does not. The `_s` forms are a TAINT channel
// even though they are overflow-safe: bounds-checking is not sanitization.
func TestTaintSourceFilter_CopyFunctions(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "copy.c")
	src := `#include <stdlib.h>
#include <string.h>

int unsafe_strcpy(void) {
    char cmd[64];
    strcpy(cmd, getenv("CMD"));
    system(cmd);
    return 0;
}

int safe_strcpy_s(void) {
    char cmd[64];
    strcpy_s(cmd, sizeof(cmd), getenv("CMD"));
    system(cmd);
    return 0;
}

int append_strcat(void) {
    char cmd[64] = "";
    strcat(cmd, getenv("CMD"));
    system(cmd);
    return 0;
}

int copy_memcpy(void) {
    char cmd[64];
    char *src = getenv("CMD");
    memcpy(cmd, src, 8);
    system(cmd);
    return 0;
}

int dup_strdup(void) {
    char *cmd = strdup(getenv("CMD"));
    system(cmd);
    return 0;
}

int clean_strcpy(void) {
    char cmd[64];
    strcpy(cmd, "/bin/ls");
    system(cmd);
    return 0;
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

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	for _, fn := range []string{"unsafe_strcpy", "safe_strcpy_s", "append_strcat", "copy_memcpy", "dup_strdup"} {
		c, ok := byFunc[fn]
		if !ok {
			t.Errorf("expected %s (copy-function taint) to be kept, got %v", fn, candidateNames(result))
			continue
		}
		if !hasTaintEvidence(c) {
			t.Errorf("expected %s to carry a taint_source evidence fragment, got %+v", fn, c.Evidence)
		}
	}
	if _, ok := byFunc["clean_strcpy"]; ok {
		t.Errorf("expected clean_strcpy (strcpy of a literal) to be suppressed, got %v", candidateNames(result))
	}
}

// TestTaintSourceFilter_FieldSubscriptSink locks in field/subscript sink
// recognition: a sink on `s->path` or `paths[0]` resolves to the same location a
// field/subscript assignment tainted, so the candidate is kept (and confirmed)
// instead of being kept only because the sink variable was unresolvable.
func TestTaintSourceFilter_FieldSubscriptSink(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "field.c")
	src := `#include <stdlib.h>
#include <stdio.h>

struct cfg { char *path; };

int field_sink(struct cfg *s) {
    s->path = getenv("HOME");
    FILE *f = fopen(s->path, "r");
    return f != 0;
}

int subscript_sink(void) {
    char *paths[2];
    paths[0] = getenv("HOME");
    FILE *f = fopen(paths[0], "r");
    return f != 0;
}

int clean_field_sink(struct cfg *s) {
    s->path = "/tmp/x";
    FILE *f = fopen(s->path, "r");
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

	for _, fn := range []string{"field_sink", "subscript_sink"} {
		c, ok := byFunc[fn]
		if !ok {
			t.Errorf("expected %s (field/subscript sink tainted) to be kept, got %v", fn, candidateNames(result))
			continue
		}
		if !hasTaintEvidence(c) {
			t.Errorf("expected %s to carry a taint_source evidence fragment, got %+v", fn, c.Evidence)
		}
	}
	if _, ok := byFunc["clean_field_sink"]; ok {
		t.Errorf("expected clean_field_sink (field assigned a literal) to be suppressed, got %v", candidateNames(result))
	}
}

// TestTaintSourceFilter_SQLInjectionConstChar locks in the call-site const
// analysis (方案 A) and const char* heuristic (方案 B) for SQL injection: a
// non-static function whose const char* SQL parameter is never reached by
// tainted data at any known call site is dropped, while a tainted caller
// confirms it and a non-const parameter with no caller is conservatively kept.
func TestTaintSourceFilter_SQLInjectionConstChar(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "sql.c")
	src := `#include <sqlite3.h>
#include <stdlib.h>

void safe_query(sqlite3 *db, const char *q) {
    sqlite3_exec(db, q, NULL, NULL, NULL);
}

void safe_query_literal(sqlite3 *db, const char *q) {
    sqlite3_exec(db, q, NULL, NULL, NULL);
}

void tainted_query(sqlite3 *db, const char *q) {
    sqlite3_exec(db, q, NULL, NULL, NULL);
}

void nonconst_query(sqlite3 *db, char *q) {
    sqlite3_exec(db, q, NULL, NULL, NULL);
}

void use_safe(sqlite3 *db) {
    const char *sql = "SELECT * FROM users";
    safe_query(db, sql);
}

void use_safe_literal(sqlite3 *db) {
    safe_query_literal(db, "SELECT * FROM users");
}

void use_tainted(sqlite3 *db) {
    const char *sql = getenv("QUERY");
    tainted_query(db, sql);
}

void use_nonconst(sqlite3 *db) {
    nonconst_query(db, "x");
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

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	if _, ok := byFunc["safe_query"]; ok {
		t.Errorf("safe_query (const char* param, identifier caller with no taint) should be dropped by call-site const analysis, got %v", candidateNames(result))
	}
	if _, ok := byFunc["safe_query_literal"]; ok {
		t.Errorf("safe_query_literal (const char* param, literal caller) should be dropped by const char* heuristic, got %v", candidateNames(result))
	}
	tq, ok := byFunc["tainted_query"]
	if !ok {
		t.Errorf("tainted_query (tainted caller) should be confirmed (kept), got %v", candidateNames(result))
	} else if !hasTaintEvidence(tq) {
		t.Errorf("tainted_query should carry taint_source evidence, got %+v", tq.Evidence)
	}
	if _, ok := byFunc["nonconst_query"]; !ok {
		t.Errorf("nonconst_query (non-const param, no caller) should be kept, got %v", candidateNames(result))
	}
}

// TestTaintSourceFilter_SQLSafeFuncsAndSinks locks in the Annex K safe-format
// variants (snprintf_s / sprintf_s) as SQL taint channels and the expanded SQL
// sink set (mysql_query etc.). Previously the detector and formatCopies only
// recognized sprintf/snprintf, so a query built with snprintf_s and executed
// via mysql_query was a silent false negative.
func TestTaintSourceFilter_SQLSafeFuncsAndSinks(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "sqlsafe.c")
	src := `#include <sqlite3.h>
#include <stdlib.h>

void snprintf_s_tainted(sqlite3 *db) {
    char buf[256];
    const char *name = getenv("USER");
    snprintf_s(buf, sizeof(buf), "SELECT * FROM users WHERE name = '%s'", name);
    sqlite3_exec(db, buf, NULL, NULL, NULL);
}

void sprintf_s_tainted(sqlite3 *db) {
    char buf[256];
    const char *name = getenv("USER");
    sprintf_s(buf, sizeof(buf), "SELECT * FROM users WHERE name = '%s'", name);
    sqlite3_exec(db, buf, NULL, NULL, NULL);
}

void snprintf_s_safe(sqlite3 *db) {
    char buf[256];
    snprintf_s(buf, sizeof(buf), "SELECT * FROM users WHERE id = %d", 42);
    sqlite3_exec(db, buf, NULL, NULL, NULL);
}

void mysql_tainted(void *conn) {
    char buf[256];
    const char *name = getenv("USER");
    sprintf(buf, "SELECT * FROM t WHERE name = '%s'", name);
    mysql_query(conn, buf);
}

void mysql_safe(void *conn) {
    char buf[256];
    sprintf(buf, "SELECT * FROM users WHERE id = %d", 42);
    mysql_query(conn, buf);
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

	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}

	for _, fn := range []string{"snprintf_s_tainted", "sprintf_s_tainted", "mysql_tainted"} {
		c, ok := byFunc[fn]
		if !ok {
			t.Errorf("expected %s (taint via safe-func / expanded sink) to be kept, got %v", fn, candidateNames(result))
			continue
		}
		if !hasTaintEvidence(c) {
			t.Errorf("expected %s to carry taint_source evidence, got %+v", fn, c.Evidence)
		}
	}
	for _, fn := range []string{"snprintf_s_safe", "mysql_safe"} {
		if _, ok := byFunc[fn]; ok {
			t.Errorf("expected %s (literal arg, no taint) to be suppressed, got %v", fn, candidateNames(result))
		}
	}
}
