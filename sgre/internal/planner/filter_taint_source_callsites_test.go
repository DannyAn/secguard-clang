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

// setupCallsiteFixture indexes src, runs the graph builders + the format-string
// and path-traversal detectors, and returns a fresh Planner's plan for
// vulnType (detectors run once; each Plan call re-seeds from the same events).
func setupCallsiteFixture(t *testing.T, src string, vulnType string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "census.c")
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
	evidence.NewPathTraversalDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, vulnType)
	if err != nil {
		t.Fatalf("plan %s: %v", vulnType, err)
	}
	return result
}

func candidatesByFunc(result *PlanResult) map[string]EvidenceItem {
	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}
	return byFunc
}

func hasTokenPrefix(tokens []string, prefix string) bool {
	for _, tok := range tokens {
		if len(tok) >= len(prefix) && tok[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func hasEvidenceFragment(frags []EvidenceFragment, fragType string) bool {
	for _, f := range frags {
		if f.Type == fragType {
			return true
		}
	}
	return false
}

// TestCallsiteCensus_AllLiteralGateDropped locks in the call-site gate for a
// NON-static function: when every in-tree direct caller passes a compile-time
// constant to the sink parameter, the parameter is not attacker-reachable and
// the candidate is dropped instead of being handed to the AI as suspected
// (the svn_output_dbg false-positive shape).
func TestCallsiteCensus_AllLiteralGateDropped(t *testing.T) {
	src := `#include <stdio.h>

void log_open(const char *fmt) {
    fprintf(stderr, fmt);
}

int main(void) {
    log_open("service started\n");
    log_open("service stopped\n");
    return 0;
}
`
	result := setupCallsiteFixture(t, src, "format-string")
	if _, ok := candidatesByFunc(result)["log_open"]; ok {
		t.Errorf("log_open (all in-tree call sites pass literals) should be dropped, got %v", candidateNames(result))
	}
}

// TestCallsiteCensus_VarCallSiteKeptWithToken locks in the complementary
// case: a non-constant (variable) call-site argument blocks the gate, the
// candidate stays suspected, and the classifier receives the census — both as
// the callsites@ hint token and as a callsite_census evidence fragment.
func TestCallsiteCensus_VarCallSiteKeptWithToken(t *testing.T) {
	src := `#include <stdio.h>

void log_open(const char *fmt) {
    fprintf(stderr, fmt);
}

int main(void) {
    char env[32] = "dyn";
    log_open("service started\n");
    log_open(env);
    return 0;
}
`
	result := setupCallsiteFixture(t, src, "format-string")
	item, ok := candidatesByFunc(result)["log_open"]
	if !ok {
		t.Fatalf("log_open (one variable call-site argument) should be kept, got %v", candidateNames(result))
	}
	if !hasTokenPrefix(item.HintTokens, "callsites@2:1-literal,1-var") {
		t.Errorf("log_open hint tokens should carry callsites@2:1-literal,1-var, got %v", item.HintTokens)
	}
	if !hasEvidenceFragment(item.Evidence, "callsite_census") {
		t.Errorf("log_open evidence should carry a callsite_census fragment, got %+v", item.Evidence)
	}
	found := false
	for _, f := range item.VerdictFacts {
		if len(f.Token) >= 10 && f.Token[:10] == "callsites@" {
			found = true
		}
	}
	if !found {
		t.Errorf("log_open verdict facts should carry callsites@, got %+v", item.VerdictFacts)
	}
}

// TestCallsiteCensus_TaintedCallSitePromotes locks in that a call site passing
// a DIRECT taint source is unaffected by the gate: the parameter is proven
// tainted and the candidate is promoted to confirmed.
func TestCallsiteCensus_TaintedCallSitePromotes(t *testing.T) {
	src := `#include <stdio.h>
#include <stdlib.h>

void log_t(const char *fmt) {
    fprintf(stderr, fmt);
}

int main(void) {
    log_t(getenv("FORMAT"));
    return 0;
}
`
	result := setupCallsiteFixture(t, src, "format-string")
	item, ok := candidatesByFunc(result)["log_t"]
	if !ok {
		t.Fatalf("log_t (tainted call-site argument) should be kept, got %v", candidateNames(result))
	}
	if !hasTaintEvidence(item) || item.SuspicionLevel != "confirmed" {
		t.Errorf("log_t should be promoted to confirmed with a taint source, got level=%s evidence=%+v", item.SuspicionLevel, item.Evidence)
	}
}

// TestCallsiteCensus_AddressTakenKeeps locks in the address-taken guard: a
// function referenced through a function pointer (here via plain-name decay,
// not &fn) has callers the direct-call census cannot see, so the all-literal
// gate must not fire.
func TestCallsiteCensus_AddressTakenKeeps(t *testing.T) {
	src := `#include <stdio.h>

void log_cb(const char *fmt) {
    fprintf(stderr, fmt);
}

int main(void) {
    void (*fp)(const char *) = log_cb;
    log_cb("boot\n");
    fp("run\n");
    return 0;
}
`
	result := setupCallsiteFixture(t, src, "format-string")
	if _, ok := candidatesByFunc(result)["log_cb"]; !ok {
		t.Errorf("log_cb (referenced through a function pointer) should be kept, got %v", candidateNames(result))
	}
}

// TestSanitizeKill_StrrchrDropsPathKeepsFormat locks in the path-traversal-
// only sanitize kill: `base = strrchr(path, '/')` kills the target's PATH
// taint (the fallback-copy shape `base = path; base = strrchr(...)` is the
// false-positive source), while the format-string flow for the SAME variable
// keeps the copy-propagated taint — a sanitized filename still carries format
// specifiers.
func TestSanitizeKill_StrrchrDropsPathKeepsFormat(t *testing.T) {
	src := `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mixed_sinks(void) {
    char *path = getenv("USER_FILE");
    if (path == NULL) return -1;
    char *base = path;
    base = strrchr(path, '/');
    if (base == NULL) return -1;
    remove(base);
    printf(base);
    return 0;
}
`
	pathResult := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(pathResult)["mixed_sinks"]; ok {
		t.Errorf("mixed_sinks path candidate should be dropped by the strrchr sanitize kill, got %v", candidateNames(pathResult))
	}

	fmtResult := setupCallsiteFixture(t, src, "format-string")
	item, ok := candidatesByFunc(fmtResult)["mixed_sinks"]
	if !ok {
		t.Fatalf("mixed_sinks format candidate must NOT be dropped by the sanitize kill, got %v", candidateNames(fmtResult))
	}
	if !hasTaintEvidence(item) {
		t.Errorf("mixed_sinks format candidate should keep the copy-propagated taint (base = path), got %+v", item.Evidence)
	}
}

// TestSanitizeKill_BasenameDrops locks in the basename tier of the sanitize
// kill (the apikb builtin table, no '/' separator involved).
func TestSanitizeKill_BasenameDrops(t *testing.T) {
	src := `#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>

int rm_basename(void) {
    char *path = getenv("USER_FILE");
    if (path == NULL) return -1;
    char *base = path;
    base = basename(path);
    if (base == NULL) return -1;
    return remove(base);
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["rm_basename"]; ok {
		t.Errorf("rm_basename should be dropped by the basename sanitize kill, got %v", candidateNames(result))
	}
}

// TestSanitizeKill_PointerArithmeticSink locks in the trailing-integer
// pointer-arithmetic sink (`fopen(seg + 1, ...)` — the canonical strrchr
// filename-extraction idiom): the sink key must resolve to the base
// identifier so the sanitize kill applies.
func TestSanitizeKill_PointerArithmeticSink(t *testing.T) {
	src := `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int open_tail(void) {
    char *path = getenv("USER_FILE");
    if (path == NULL) return -1;
    char *seg = strrchr(path, '/');
    if (seg == NULL) return -1;
    FILE *f = fopen(seg + 1, "r");
    if (f == NULL) return -1;
    fclose(f);
    return 0;
}
`
	result := setupCallsiteFixture(t, src, "path-traversal")
	if _, ok := candidatesByFunc(result)["open_tail"]; ok {
		t.Errorf("open_tail (fopen(strrchr(path,'/') + 1)) should be dropped by the sanitize kill, got %v", candidateNames(result))
	}
}
