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

func planNullDeref(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "nd.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// TestNullDeref_OutputParamWriteNotFlagged pins the dominant production false
// positive: `*out = f()` writes THROUGH the output parameter; it is not "out =
// f()". Before assignedVariable stopped attributing `*out` to "out", the write
// marked the output parameter as a nullable source and the very next
// `if (*out == NULL)` read as a null-deref. This covers both `void **out` and
// the typedef-hidden `handle_t *out` (typedef void *handle_t) shape.
func TestNullDeref_OutputParamWriteNotFlagged(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdint.h>

typedef void *handle_t;

static int example_register_by_name(const char *name) { (void)name; return 0; }
static void *example_get_by_name(const char *name) {
    if (name == NULL) return NULL;
    return malloc(1);
}

uint32_t example_function(const char *name, handle_t *thread_id)
{
    if (example_register_by_name(name) != 0) {
        return 1;
    }
    *thread_id = example_get_by_name(name);
    if (*thread_id == NULL) {
        return 1;
    }
    return 0;
}

int main(void) {
    handle_t id = NULL;
    return (int)example_function("x", &id);
}
`
	result := planNullDeref(t, src)
	if c := candidateForFunc(t, result, "example_function"); c != nil {
		t.Errorf("example_function() output-param write must NOT be a null-deref, got: %s", candidateNames(result))
	}
}

// TestNullDeref_RealNullStillFlagged guards against over-suppression: a genuine
// `p = NULL; *p = 1` (write through a NULL pointer) and an unchecked
// `malloc` deref must still be reported.
func TestNullDeref_RealNullStillFlagged(t *testing.T) {
	src := `#include <stdlib.h>

static int real_null_write(void) {
    int *p = NULL;
    *p = 1;
    return 0;
}

static int real_null_malloc(int n) {
    int *p = (int *)malloc(sizeof(int) * n);
    return *p;
}

int main(void) { return real_null_write() + real_null_malloc(1); }
`
	result := planNullDeref(t, src)
	if c := candidateForFunc(t, result, "real_null_write"); c == nil {
		t.Errorf("real_null_write() (p=NULL; *p=1) must be flagged, got: %s", candidateNames(result))
	}
	if c := candidateForFunc(t, result, "real_null_malloc"); c == nil {
		t.Errorf("real_null_malloc() (unchecked malloc deref) must be flagged, got: %s", candidateNames(result))
	}
}
