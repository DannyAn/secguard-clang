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

// TestNullDeref_CallResultDirectDeref pins the v0.7.3 gap: a function returning
// a NULL-able global field, dereferenced DIRECTLY at the call site
// (`get_shell_cfg()->detect_time`) with no intervening variable, must be
// reported. The earlier fix only covered `p = get_shell_cfg(); p->field`.
func TestNullDeref_CallResultDirectDeref(t *testing.T) {
	src := `typedef struct {
    unsigned int detect_time;
} shell_config_t;

typedef struct tag_space_s {
    shell_config_t *shell_conf;
} space_s;

static space_s g_space = {0};

shell_config_t *get_shell_cfg(void) {
    return g_space.shell_conf;
}

void get_cfg(void) {
    unsigned int x = get_shell_cfg()->detect_time;
    (void)x;
}
`
	result := planNullDerefSrc(t, src)
	if !hasNullDerefCandidate(result, "get_cfg") {
		t.Errorf("get_cfg null-deref (direct deref of get_shell_cfg()->detect_time) was missed; candidates=%v", candidateNames(result))
	}
}

// TestNullDeref_CallResultDirectDerefStar covers the `*f()` form: a NULL-able
// return value dereferenced explicitly via pointer_expression.
func TestNullDeref_CallResultDirectDerefStar(t *testing.T) {
	src := `typedef struct {
    unsigned int detect_time;
} shell_config_t;

typedef struct tag_space_s {
    shell_config_t *shell_conf;
} space_s;

static space_s g_space = {0};

shell_config_t *get_shell_cfg(void) {
    return g_space.shell_conf;
}

void use_star(void) {
    shell_config_t s = *get_shell_cfg();
    (void)s;
}
`
	result := planNullDerefSrc(t, src)
	if !hasNullDerefCandidate(result, "use_star") {
		t.Errorf("use_star null-deref (direct deref of *get_shell_cfg()) was missed; candidates=%v", candidateNames(result))
	}
}

// TestNullDeref_CallResultDirectDerefSubscript covers the `f()[i]` form: a
// NULL-able return value dereferenced via subscript_expression.
func TestNullDeref_CallResultDirectDerefSubscript(t *testing.T) {
	src := `typedef struct {
    int *arr;
} cfg_t;

static cfg_t g_cfg = {0};

int *get_arr(void) {
    return g_cfg.arr;
}

int use_subscript(void) {
    return get_arr()[0];
}
`
	result := planNullDerefSrc(t, src)
	if !hasNullDerefCandidate(result, "use_subscript") {
		t.Errorf("use_subscript null-deref (direct deref of get_arr()[0]) was missed; candidates=%v", candidateNames(result))
	}
}

// TestNullDeref_CallResultDirectDerefAddressOfNotNullable pins the precision
// side: `return &g_config` is an address (always non-null), so directly
// dereferencing the call result must NOT be flagged.
func TestNullDeref_CallResultDirectDerefAddressOfNotNullable(t *testing.T) {
	src := `typedef struct { int x; } config_t;
static config_t g_config;

config_t *get_nonnull_cfg(void) {
    return &g_config;
}

void use_nonnull(void) {
    int x = get_nonnull_cfg()->x;
    (void)x;
}
`
	result := planNullDerefSrc(t, src)
	if hasNullDerefCandidate(result, "use_nonnull") {
		t.Errorf("use_nonnull must NOT be flagged (get_nonnull_cfg returns &g_config, always non-null); candidates=%v", candidateNames(result))
	}
}
