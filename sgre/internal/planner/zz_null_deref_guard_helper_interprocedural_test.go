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

func planNullDerefHelperFull(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "helper_full.c")
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
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewInterproceduralDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// TestNullDeref_GuardHelperInterproceduralCallSite pins the interprocedural half
// of the null-check-predicate helper: `if (is_empty(p)) goto out;` must not flag
// the call site itself as a null-deref of p. The helper derefs its parameter
// only on the guarded, non-null branch (`p == NULL || p->content == NULL ...`),
// so the callee's parameter counts as null-guarded and the caller's call is safe.
func TestNullDeref_GuardHelperInterproceduralCallSite(t *testing.T) {
	src := `#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>

typedef struct { char *content; size_t length; } string_data_t;

static bool is_empty_string(string_data_t *data)
{
    return (data == NULL || data->content == NULL || data->length == 0) ? true : false;
}

int format_string(char *buffer, char *end_buffer, const char *format, va_list arguments) {
    char *current_ptr = buffer;
    string_data_t *string_data = NULL;

    while (*format && current_ptr < end_buffer) {
        size_t max_size = end_buffer - current_ptr;
        if (*format != '%') {
            *(current_ptr++) = *(format++);
            continue;
        }

        if (*(format + 1) == 'V') {
            string_data = va_arg(arguments, string_data_t *);
            if (is_empty_string(string_data)) {
                goto finished;
            }
        }
    }

finished:
    return 0;
}
`
	result := planNullDerefHelperFull(t, src)
	if c := candidateForFunc(t, result, "format_string"); c != nil {
		t.Errorf("format_string should NOT be flagged (is_empty_string null-checks its param, so the call site is guarded), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// TestNullDeref_InterproceduralDerefCallee_Control is the control: a callee that
// dereferences its parameter WITHOUT a null check must still flag a caller that
// passes a nullable pointer into it. This guards against over-suppression.
func TestNullDeref_InterproceduralDerefCallee_Control(t *testing.T) {
	src := `#include <stdlib.h>

typedef struct { int x; } msg_t;

static void send_msg(msg_t *m) {
    m->x = 1;
}

int caller(void) {
    msg_t *m = (msg_t *)malloc(sizeof(msg_t));
    send_msg(m);
    return 0;
}
`
	result := planNullDerefHelperFull(t, src)
	if c := candidateForFunc(t, result, "caller"); c == nil {
		t.Errorf("caller should STAY flagged (send_msg derefs its param without a null check, and m is nullable)")
	}
}
