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

// planMemoryLeak runs the full memory-leak pipeline and returns the converged
// candidates keyed by function name.
func planMemoryLeak(t *testing.T, src string) map[string]EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "ml.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := graph.NewCallGraphBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := graph.NewDataFlowBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := graph.NewOwnershipBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := evidence.NewMemoryLeakDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "memory-leak")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	out := map[string]EvidenceItem{}
	for _, c := range res.Candidates {
		out[c.Target.Function] = c
	}
	return out
}

// ML-05: free(q) where q = p releases p's block — no leak.
// ML-06: free((void*)p) releases p — no leak.
func TestMemoryLeakReview_AliasAndCastRelease(t *testing.T) {
	src := `#include <stdlib.h>
int alias_free(int c) {
    int *p = malloc(8);
    int *q = p;
    free(q);
    return 0;
}
int cast_free(int c) {
    int *p = malloc(8);
    free((void *)p);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["alias_free"]; ok {
		t.Errorf("alias_free: free(q) with q=p must not leak p, got %v", keysOf(got))
	}
	if _, ok := got["cast_free"]; ok {
		t.Errorf("cast_free: free((void*)p) must not leak p, got %v", keysOf(got))
	}
}

// ML-07: g = (T*)p escapes p; ML-09: extern-declared global store escapes p.
func TestMemoryLeakReview_EscapeVariants(t *testing.T) {
	src := `#include <stdlib.h>
extern int *g1;
int cast_escape(int c) {
    int *p = malloc(8);
    g1 = (int *)p;
    return 0;
}
int extern_global(int c) {
    extern int *global_buf;
    int *p = malloc(8);
    global_buf = p;
    return 0;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["cast_escape"]; ok {
		t.Errorf("cast_escape: g1 = (int*)p escapes p, got %v", keysOf(got))
	}
	if _, ok := got["extern_global"]; ok {
		t.Errorf("extern_global: store to extern global escapes p, got %v", keysOf(got))
	}
}

// ML-11: implicit allocators (strdup / asprintf / getline / realpath(NULL)) are
// allocations and leak when never freed.
func TestMemoryLeakReview_ImplicitAllocators(t *testing.T) {
	src := `#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int strdup_leak(void) {
    char *p = strdup("x");
    return 0;
}
int asprintf_leak(int c) {
    char *p = 0;
    asprintf(&p, "%d", c);
    return 0;
}
int getline_leak(int c) {
    char *p = 0;
    size_t n = 0;
    getline(&p, &n, stdin);
    return 0;
}
int realpath_leak(void) {
    char *p = realpath("/tmp", 0);
    return 0;
}
int strdup_free(void) {
    char *p = strdup("x");
    free(p);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	for _, fn := range []string{"strdup_leak", "asprintf_leak", "getline_leak", "realpath_leak"} {
		if _, ok := got[fn]; !ok {
			t.Errorf("%s: implicit allocation must be reported, got %v", fn, keysOf(got))
		}
	}
	if _, ok := got["strdup_free"]; ok {
		t.Errorf("strdup_free: freed, must not leak, got %v", keysOf(got))
	}
}

// NAT production feedback: 55 asprintf-related memory-leak findings (part of
// the 239/271 = 88% false-positive batch). The
// asprintf→fail/fail_nc_err/transapi_comm_with_vrp framework pattern hands
// the allocation to an external function that takes ownership and releases
// it — the `return f(...)` is directly returned, the variable is never used
// afterwards, and f's name carries the error-handling / comm semantics
// (fail / *_err* / *_comm* / *_send*). That shape is an escape, not a leak.
func TestMemoryLeakReview_AsprinfFrameworkEscape(t *testing.T) {
	src := `#include <stdio.h>
#include <stdlib.h>

struct nc_err;
extern int fail(struct nc_err **err, char *msg, int ret);
extern int fail_nc_err(struct nc_err **err, char *msg, char *path, int ret, unsigned int err_code);
extern int transapi_comm_with_vrp(void *header, int op, void *rcv_data, struct nc_err **error, char *path);

int nat_set_name(void *error) {
    char *err_msg = NULL;
    asprintf(&err_msg, "name is NULL");
    return fail(error, err_msg, EXIT_FAILURE);
}

int nat_validate(void *error) {
    char *err_msg = NULL;
    char *path_message = NULL;
    asprintf(&err_msg, "validation error");
    asprintf(&path_message, "module:container:[field]");
    return fail_nc_err(error, err_msg, path_message, EXIT_FAILURE, 1001);
}

int nat_send(void *header, int op, void *rcv_data, struct nc_err **error, const char *key) {
    char *path_message = NULL;
    asprintf(&path_message, "/hw-nat/key=[%s]", key);
    return transapi_comm_with_vrp(header, op, rcv_data, error, path_message);
}

int leak_no_transfer(void) {
    char *p = NULL;
    asprintf(&p, "x");
    return 0;
}

int leak_printf(void) {
    char *p = NULL;
    asprintf(&p, "x");
    return printf("%s", p);
}
`
	got := planMemoryLeak(t, src)
	for _, fn := range []string{"nat_set_name", "nat_validate", "nat_send"} {
		if _, ok := got[fn]; ok {
			t.Errorf("%s: asprintf→ownership-taking external callee (fail/fail_nc_err/transapi_comm_with_vrp) must NOT leak (escape), got %v", fn, keysOf(got))
		}
	}
	for _, fn := range []string{"leak_no_transfer", "leak_printf"} {
		if _, ok := got[fn]; !ok {
			t.Errorf("%s: asprintf without an ownership transfer (no call / printf does not take ownership) must STAY leak, got %v", fn, keysOf(got))
		}
	}
}

// ML-12: self-realloc leaks the OLD block on failure; realloc-into-temp does not
// leak the source.
func TestMemoryLeakReview_Realloc(t *testing.T) {
	src := `#include <stdlib.h>
int self_realloc(int c) {
    int *p = malloc(8);
    p = realloc(p, 16);
    free(p);
    return 0;
}
int safe_realloc(int c) {
    int *p = malloc(8);
    int *tmp = realloc(p, 16);
    free(tmp);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["self_realloc"]; !ok {
		t.Errorf("self_realloc: p=realloc(p,n) leaks the old block on failure, got %v", keysOf(got))
	}
	if _, ok := got["safe_realloc"]; ok {
		t.Errorf("safe_realloc: realloc into a temp consumes p, must not leak, got %v", keysOf(got))
	}
}

// ML-01/18: a pointer with no free/transfer/escape is a DEFINITE leak and must
// be confirmed; a conditional free stays suspected.
func TestMemoryLeakReview_Confirmed(t *testing.T) {
	src := `#include <stdlib.h>
int definite(void) {
    int *p = malloc(8);
    return 0;
}
int conditional(int c) {
    int *p = malloc(8);
    if (c) free(p);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	c, ok := got["definite"]
	if !ok {
		t.Fatalf("definite must be a candidate, got %v", keysOf(got))
	}
	// The "definite leak" proof (no free/escape/transfer) was found unsound on
	// real-world code (custom deallocators/containers the closed-world escape
	// analysis cannot see), so it no longer auto-confirms — it stays suspected
	// for the AI, exactly like the conditional case.
	if c.SuspicionLevel != "suspected" {
		t.Errorf("definite (never freed/escaped/returned) should stay suspected (auto-confirm demoted), got %q", c.SuspicionLevel)
	}
	if cc, ok := got["conditional"]; ok && cc.SuspicionLevel == "confirmed" {
		t.Errorf("conditional (freed on one path only) must stay suspected, got %q", cc.SuspicionLevel)
	}
}

// ML-13: a create function with a paired destroy must NOT be blanket-exempted —
// a temporary allocation it never returns/frees is a genuine leak and must be
// reported, while the returned pointer is a transfer.
func TestMemoryLeakReview_RAIICoarseExemption(t *testing.T) {
	src := `#include <stdlib.h>
void *foo_new(void) {
    void *p = malloc(16);
    void *tmp = malloc(8);
    return p;
}
void foo_free(void *p) { free(p); }
`
	got := planMemoryLeak(t, src)
	if _, ok := got["foo_new"]; !ok {
		t.Errorf("foo_new: the temporary tmp leaks and must be reported, got %v", keysOf(got))
	}
}

// ML-15: a cast-wrapped return (`return (T *)p`) is an ownership transfer, not a
// leak.
func TestMemoryLeakReview_CastWrappedReturn(t *testing.T) {
	src := `#include <stdlib.h>
int *cast_return(void) {
    int *p = malloc(8);
    return (int *)p;
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["cast_return"]; ok {
		t.Errorf("cast_return: return (int*)p transfers ownership, must not leak, got %v", keysOf(got))
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// L2 (issue #328): a call that receives the allocated pointer as an argument
// but is neither a recognized release nor a recognized ownership transfer is
// an unmodeled hand-off — it must surface as transfer-unknown@<api>:<line> so
// the classifier opens the Code Context instead of trusting leak@definite +
// escape@none. db_attach carries no release/transfer spelling, so the
// closed-world analysis cannot see that it may take ownership.
func TestMemoryLeakReview_TransferUnknown(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdio.h>

void db_attach(void *parent, void *obj);

int idm_import(void *parent) {
    void *p = malloc(64);
    db_attach(parent, p);
    return 0;
}

int asprintf_only(int c) {
    char *p = 0;
    asprintf(&p, "%d", c);
    return 0;
}
`
	got := planMemoryLeak(t, src)
	c, ok := got["idm_import"]
	if !ok {
		t.Fatalf("idm_import must be a candidate, got %v", keysOf(got))
	}
	found := false
	for _, tok := range c.HintTokens {
		if strings.HasPrefix(tok, "transfer-unknown@db_attach:") {
			found = true
		}
	}
	if !found {
		t.Errorf("idm_import must carry transfer-unknown@db_attach:<line>, got %v", c.HintTokens)
	}
	if c.SuspicionLevel != "suspected" {
		t.Errorf("unmodeled-transfer leak must stay suspected for the AI, got %q", c.SuspicionLevel)
	}

	// The out-param allocator itself (&p to asprintf) is the allocation, not a
	// transfer — it must NOT be flagged as transfer-unknown.
	if a, ok := got["asprintf_only"]; ok {
		for _, tok := range a.HintTokens {
			if strings.HasPrefix(tok, "transfer-unknown@") {
				t.Errorf("asprintf_only: the allocation call must not be a transfer-unknown, got %v", a.HintTokens)
			}
		}
	} else {
		t.Errorf("asprintf_only must be a candidate, got %v", keysOf(got))
	}
}

// issue #281 M1 residual: a business-named release helper (`table_teardown`)
// whose body does `free(t)` releases the argument even though the name carries
// no free/destroy/delete/cleanup/recycle spelling. It must NOT be reported as a
// leak (the name heuristic alone missed it).
func TestMemoryLeakReview_ArbitraryNamedFreeHelper(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct Table { int *items; } Table;

void table_teardown(Table *t) {
    free(t);
}

void build(void) {
    Table *t = malloc(sizeof(Table));
    if (!t) return;
    table_teardown(t);
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["build"]; ok {
		t.Errorf("build: table_teardown(t) frees t directly, must not leak, got %v", keysOf(got))
	}
}

// issue #281 M1 residual, supplement §6.1: a helper that releases ONLY a field
// of its argument (`free(t->items)`) does NOT release the base pointer, so the
// base allocation still leaks and must be reported.
func TestMemoryLeakReview_FieldOnlyFreeHelperKeepsLeak(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct Table { int *items; } Table;

void table_clear(Table *t) {
    free(t->items);
}

void build(void) {
    Table *t = malloc(sizeof(Table));
    if (!t) return;
    t->items = malloc(16);
    table_clear(t);
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["build"]; !ok {
		t.Errorf("build: table_clear(t) frees only t->items, the Table base still leaks, got %v", keysOf(got))
	}
}

// issue #302: a business-named release helper may free a NON-first parameter
// (`release(int n, T *t)` frees t, the second argument). The old code only read
// ParamDirectFrees[0], so it missed the release and reported a false-positive
// leak on the caller's second argument.
func TestMemoryLeakReview_NonFirstParamFreeHelper(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct Table { int *items; } Table;

void release_after(int n, Table *t) {
    (void)n;
    free(t);
}

void build(void) {
    Table *t = malloc(sizeof(Table));
    if (!t) return;
    release_after(0, t);
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["build"]; ok {
		t.Errorf("build: release_after(0, t) frees its second argument t, must not leak, got %v", keysOf(got))
	}
}

// issue #302 follow-up: a HEURISTIC deallocator name (`_destroy` suffix) also
// must not assume the FIRST argument is freed — the summary's per-parameter
// facts decide. `pair_destroy(int flags, T *t)` frees its second argument, but
// the old findFrees treated every IsDeallocator name as freeing args[0] and
// reported a false-positive leak on t.
func TestMemoryLeakReview_HeuristicDeallocNonFirstParam(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct Table { int *items; } Table;

void pair_destroy(int flags, Table *t) {
    (void)flags;
    free(t);
}

void build(void) {
    Table *t = malloc(sizeof(Table));
    if (!t) return;
    pair_destroy(0, t);
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["build"]; ok {
		t.Errorf("build: pair_destroy(0, t) frees its second argument t, must not leak, got %v", keysOf(got))
	}
}

// issue #302 follow-up: a heuristic deallocator name (`_destroy` suffix) that
// frees its FIRST argument must still be recognized as a release — the summary
// path must not regress the conventional first-argument case.
func TestMemoryLeakReview_HeuristicDeallocFirstParam(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct Table { int *items; } Table;

void table_destroy(Table *t) {
    free(t);
}

void build(void) {
    Table *t = malloc(sizeof(Table));
    if (!t) return;
    table_destroy(t);
}
`
	got := planMemoryLeak(t, src)
	if _, ok := got["build"]; ok {
		t.Errorf("build: table_destroy(t) frees its first argument t, must not leak, got %v", keysOf(got))
	}
}
