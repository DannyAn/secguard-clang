//go:build !nosqlite

package planner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// The caller-side non-null proof must cover the three guard idioms beyond the
// early-return: the positive branch (`if (p != NULL) f(p)`), the short-circuit
// (`p != NULL && f(p)`), and the assert precondition (`assert(p != NULL);
// f(p)`). A caller using any of them proves the argument non-null, so the
// callee must not grow a caller_null seed. The else branch of a positive
// guard proves nothing (`if (p != NULL) {} else { f(p) }` still sees p NULL)
// and stays a seed.
func TestCallerGuardKinds(t *testing.T) {
	src := `#include <assert.h>

typedef struct { int field; } Context;

int process_branch(Context *ctx) { ctx->field = 1; return 0; }
int process_short(Context *ctx)  { ctx->field = 2; return 0; }
int process_assert(Context *ctx) { ctx->field = 3; return 0; }
int process_else(Context *ctx)   { ctx->field = 4; return 0; }
int process_none(Context *ctx)   { ctx->field = 5; return 0; }

void caller_positive_branch(Context *ctx) {
    if (ctx != NULL) {
        process_branch(ctx);
    }
}

int caller_short_circuit(Context *ctx) {
    return ctx != NULL && process_short(ctx) == 0;
}

void caller_assert(Context *ctx) {
    assert(ctx != NULL);
    process_assert(ctx);
}

void caller_negative_else(Context *ctx) {
    if (ctx != NULL) {
        ctx->field = 0;
    } else {
        process_else(ctx);
    }
}

void caller_unguarded(Context *ctx) {
    process_none(ctx);
}
`
	seeds := callerNullSeeds(t, src)

	for _, fn := range []string{"caller_unguarded", "caller_negative_else"} {
		if _, ok := seeds[fn]; !ok {
			t.Errorf("%s: an unguarded (or else-branch) caller must seed caller_null, got %v", fn, seeds)
		}
	}
	for _, fn := range []string{"caller_positive_branch", "caller_short_circuit", "caller_assert"} {
		if _, ok := seeds[fn]; ok {
			t.Errorf("%s: the caller proves the argument non-null (branch/short-circuit/assert guard); no caller_null seed expected, got %v", fn, seeds)
		}
	}
}

// callerNullSeeds runs just the CallerNullDetector and maps each seeded caller
// function name to its callee-parameter variable.
func callerNullSeeds(t *testing.T, src string) map[string]string {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "caller_guards.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := evidence.NewCallerNullDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	seeds := map[string]string{}
	for _, ev := range events {
		var props map[string]string
		if err := json.Unmarshal([]byte(ev.Properties), &props); err != nil {
			continue
		}
		if props["origin"] != "caller_null" {
			continue
		}
		seeds[props["function"]] = props["variable"]
	}
	return seeds
}
