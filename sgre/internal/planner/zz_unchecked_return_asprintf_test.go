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

// NAT production feedback (239/271 = 88% false positives): the
// asprintf→fail/fail_nc_err/transapi_comm_with_vrp framework pattern.
// asprintf's failure leaves the out-param NULL (glibc semantics), and the
// out-param is then handed to an external function — the NULL risk belongs
// to the null-deref chain (the callee may or may not handle NULL), NOT to
// unchecked-return. unchecked-return must only fire when the out-param is
// dereferenced in-function without a guard.
const asprintfFrameworkFixture = `#include <stdio.h>
#include <stdlib.h>

struct nc_err;
extern int fail(struct nc_err **err, char *msg, int ret);
extern int fail_nc_err(struct nc_err **err, char *msg, char *path, int ret, unsigned int err_code);
extern int transapi_comm_with_vrp(void *header, int op, void *rcv_data, struct nc_err **error, char *path);

/* Pattern A: asprintf + fail — out-param handed to an external callee. */
int nat_set_name(void *error) {
    char *err_msg = NULL;
    asprintf(&err_msg, "name is NULL");
    return fail(error, err_msg, EXIT_FAILURE);
}

/* Pattern B: asprintf x2 + fail_nc_err — both out-params handed over. */
int nat_validate(void *error) {
    char *err_msg = NULL;
    char *path_message = NULL;
    asprintf(&err_msg, "validation error");
    asprintf(&path_message, "module:container:[field]");
    return fail_nc_err(error, err_msg, path_message, EXIT_FAILURE, 1001);
}

/* Pattern C: asprintf + transapi_comm_with_vrp. */
int nat_send(void *header, int op, void *rcv_data, struct nc_err **error, const char *key) {
    char *path_message = NULL;
    asprintf(&path_message, "/hw-nat/key=[%s]", key);
    return transapi_comm_with_vrp(header, op, rcv_data, error, path_message);
}

/* Control: asprintf unchecked + the out-param DEREFERENCED in-function. */
int bad_use(void) {
    char *p = NULL;
    asprintf(&p, "x");
    p[0] = 'y';
    return 0;
}

/* Cross-function same-name interference guard: safe_use's p must not be
 * judged by bad_use's p[0] deref — ids is file-scoped. */
int safe_use(void) {
    char *p = NULL;
    asprintf(&p, "x");
    return 0;
}
`

func planUncheckedReturnAsprintf(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "asprintf_framework.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewUncheckedReturnDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "unchecked-return")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

func TestUncheckedReturn_AsprinfFrameworkPatterns(t *testing.T) {
	result := planUncheckedReturnAsprintf(t, asprintfFrameworkFixture)
	byFunc := map[string]EvidenceItem{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c
	}
	// Patterns A/B/C: the out-param is handed to an external callee (its NULL
	// handling is the null-deref chain's question, not unchecked-return's).
	for _, fn := range []string{"nat_set_name", "nat_validate", "nat_send"} {
		if c, ok := byFunc[fn]; ok {
			t.Errorf("%s: asprintf→external-callee must NOT flag unchecked-return (out-param handed over; NULL risk belongs to null-deref), got %q", fn, c.SuspicionLevel)
		}
	}
	// Control: in-function unguarded deref of the out-param — the direct
	// consequence unchecked-return owns.
	if _, ok := byFunc["bad_use"]; !ok {
		t.Errorf("bad_use: asprintf unchecked + in-function deref `p[0]` must STAY flagged (failure leaves p NULL)")
	}
	// Cross-function same-name guard: safe_use's `p` is never dereferenced in
	// ITS function; bad_use's `p[0]` must not leak into safe_use's judgement.
	if c, ok := byFunc["safe_use"]; ok {
		t.Errorf("safe_use: asprintf with no in-function use of `p` must NOT flag (bad_use's deref is a different function's variable), got %q", c.SuspicionLevel)
	}
}
