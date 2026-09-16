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

// TestNullDeref_GlobalFieldReturnIsNullable pins the production null-deref false
// negative: a getter returning a global struct field (`return g_space.shell_conf`,
// where the field is NULL at startup) is possibly-null. exprReturnsNullable must
// treat the field_expression as possibly-null, so the caller's unchecked
// `shell_cfg->detect_time` deref is reported.
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
	for _, c := range result.Candidates {
		if c.Target.Function == "set_detect_time" {
			return // the global-field-return null-deref survived
		}
	}
	t.Errorf("set_detect_time null-deref (get_shell_cfg returns a NULL-able global field) was missed; candidates=%v", candidateNames(result))
}
