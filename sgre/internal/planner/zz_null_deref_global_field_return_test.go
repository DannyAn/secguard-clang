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

func planNullDerefSrc(t *testing.T, src string) *PlanResult {
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

func hasNullDerefCandidate(result *PlanResult, fn string) bool {
	for _, c := range result.Candidates {
		if c.Target.Function == fn {
			return true
		}
	}
	return false
}

// TestNullDeref_GlobalFieldReturnIsNullable pins the production null-deref false
// negative: a getter returning a global struct field (`return g_space.shell_conf`,
// where the field is NULL at startup) is possibly-null.
func TestNullDeref_GlobalFieldReturnIsNullable(t *testing.T) {
	src := `typedef struct {
    unsigned int detect_time;
} shell_config_t;

typedef struct tag_space_s {
    shell_config_t *shell_conf;
    void *inst_handle;
} space_s;

static space_s g_space = {0, 0};

shell_config_t *get_shell_cfg(void) {
    return g_space.shell_conf;
}

void set_detect_time(unsigned int time) {
    shell_config_t *shell_cfg = get_shell_cfg();
    shell_cfg->detect_time = time;
}
`
	result := planNullDerefSrc(t, src)
	if !hasNullDerefCandidate(result, "set_detect_time") {
		t.Errorf("set_detect_time null-deref (get_shell_cfg returns a NULL-able global field) was missed; candidates=%v", candidateNames(result))
	}
}

// TestNullDeref_ExternalCallReturnIsNullable pins the open-world fix: a getter
// that returns the result of an EXTERNAL (undeclared-in-scan) function is
// possibly-null, so the caller's unchecked deref is reported.
func TestNullDeref_ExternalCallReturnIsNullable(t *testing.T) {
	src := `typedef struct { int x; } config_t;

config_t *external_getter(void);

config_t *get_config(void) {
    return external_getter();
}

void use_config(void) {
    config_t *c = get_config();
    c->x = 1;
}
`
	result := planNullDerefSrc(t, src)
	if !hasNullDerefCandidate(result, "use_config") {
		t.Errorf("use_config null-deref (get_config returns an external call) was missed; candidates=%v", candidateNames(result))
	}
}

// TestNullDeref_AddressOfReturnIsNotNullable pins the precision side of the
// fail-open change: `return &g_config` is an address (always non-null), so the
// caller's deref must NOT be flagged.
func TestNullDeref_AddressOfReturnIsNotNullable(t *testing.T) {
	src := `typedef struct { int x; } config_t;
static config_t g_config;

config_t *get_config(void) {
    return &g_config;
}

void use_config(void) {
    config_t *c = get_config();
    c->x = 1;
}
`
	result := planNullDerefSrc(t, src)
	if hasNullDerefCandidate(result, "use_config") {
		t.Errorf("use_config must NOT be flagged (get_config returns &g_config, always non-null); candidates=%v", candidateNames(result))
	}
}
