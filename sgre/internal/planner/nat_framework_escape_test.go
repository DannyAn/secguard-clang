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

// CLI parity regression (NAT production feedback): under the FULL detector
// set (RunAllDetectors, exactly the CLI chain), the asprintf framework
// ownership-transfer patterns must not leak, and every control must stay
// confirmed. This complements TestMemoryLeakReview_AsprinfFrameworkEscape
// (minimal detector chain) — the CLI chain is what production runs.
func TestMemoryLeak_AsprinfFrameworkEscapeFullChain(t *testing.T) {
	src := `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nc_err;
extern int fail(struct nc_err **err, char *msg, int ret);
extern int fail_nc_err(struct nc_err **err, char *msg, char *path, int ret, unsigned int err_code);
extern int transapi_comm_with_vrp(void *header, int op, void *rcv_data, struct nc_err **error, char *path);

int nat_addrgroup_set_name(struct nc_err **error, const char *name) {
    char *err_msg = NULL;
    if (name == NULL) {
        asprintf(&err_msg, "address-group name is NULL");
        return fail(error, err_msg, EXIT_FAILURE);
    }
    return 0;
}

int nat_addrgroup_validate(struct nc_err **error, const char *group) {
    char *err_msg = NULL;
    char *path_message = NULL;
    if (group == NULL) {
        asprintf(&err_msg, "validation error: group missing");
        asprintf(&path_message, "hw-nat-addrgroup:nat-address-group:[name]");
        return fail_nc_err(error, err_msg, path_message, EXIT_FAILURE, 1001);
    }
    return 0;
}

int nat_send(void *header, int op, void *rcv_data, struct nc_err **error, const char *key) {
    char *path_message = NULL;
    asprintf(&path_message, "/hw-nat-addrgroup/nat-address-group:[name = \"%s\"]", key);
    return transapi_comm_with_vrp(header, op, rcv_data, error, path_message);
}

int nat_leak_no_transfer(void) {
    char *p = NULL;
    asprintf(&p, "x");
    return 0;
}

int nat_leak_printf(void) {
    char *p = NULL;
    asprintf(&p, "x");
    return printf("%%s", p);
}

int nat_bad_use(void) {
    char *p = NULL;
    asprintf(&p, "x");
    p[0] = 'y';
    return 0;
}

int nat_malloc_unchecked(void) {
    char *p = malloc(16);
    p[0] = 'y';
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "nat.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatal(err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	for _, derr := range evidence.RunAllDetectors(ctx, store, p, logger) {
		t.Logf("detector %s error: %v", derr.Detector, derr.Err)
	}
	pl := NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "memory-leak")
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"nat_addrgroup_set_name", "nat_addrgroup_validate", "nat_send"} {
		for _, c := range res.Candidates {
			if c.Target.Function == fn {
				t.Errorf("%s: must NOT leak under the FULL detector chain (CLI parity), got %+v", fn, c.Target)
			}
		}
	}
	for _, fn := range []string{"nat_leak_no_transfer", "nat_leak_printf", "nat_bad_use", "nat_malloc_unchecked"} {
		found := false
		for _, c := range res.Candidates {
			if c.Target.Function == fn {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: control must STAY flagged under the FULL detector chain, got %d candidates", fn, len(res.Candidates))
		}
	}
}
