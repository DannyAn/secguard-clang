//go:build !nosqlite

package planner

import "testing"

// The ALL_CAPS heuristic in the macro-context detector must yield to the
// function index: a static function named with the macro convention
// (POOL_SECT, nat_null_deref_regress.c ND-15) is a scanned function
// definition, not a #define. Mis-flagging it as macro context blocks the
// auto-confirm gate in cli/scan.go (confirmed && !MacroContext), so a
// proven-nullable callee spends an AI verdict for no reason. A genuine
// undefined ALL_CAPS macro (LOCK_SECTION) keeps the flag.
func TestMacroContextExcludesDefinedFunctions(t *testing.T) {
	src := `typedef struct { int x; } sect_t;

static sect_t g_sect;
static int g_ready;

static sect_t *POOL_SECT(int id) {
    if (!g_ready) {
        return NULL;
    }
    return &g_sect;
}

#define LOCK_SECTION() do { } while (0)

int use_pool_sect(int id) {
    sect_t *s = POOL_SECT(id);
    s->x = 1;
    return 0;
}

/* Spacer: the ±8-line macro window of the dereference above must not reach
 * the genuine macro call below — this test isolates the defined-function
 * rule, not the window heuristic. */
static int g_unused_1;
static int g_unused_2;
static int g_unused_3;
static int g_unused_4;

int use_pool_sect_near_macro(int id) {
    sect_t *s = POOL_SECT(id);
    LOCK_SECTION();
    s->x = 2;
    return 0;
}
`
	result := runRetStrengthPlan(t, map[string]string{"pool_sect.c": src})

	c, ok := candidateByFunction(result, "use_pool_sect")
	if !ok {
		t.Fatalf("expected a candidate in use_pool_sect, got candidates: %v", candidateNames(result))
	}
	if c.MacroContext {
		t.Errorf("POOL_SECT is a scanned static function, not a macro: MacroContext must be false")
	}
	if c.NullOriginTier != "malloc-fail" {
		t.Errorf("proven-nullable POOL_SECT: tier = %q, want malloc-fail", c.NullOriginTier)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("without the false macro flag the confirmed verdict stands, got %q", c.SuspicionLevel)
	}

	near, ok := candidateByFunction(result, "use_pool_sect_near_macro")
	if !ok {
		t.Fatalf("expected a candidate in use_pool_sect_near_macro, got candidates: %v", candidateNames(result))
	}
	if !near.MacroContext {
		t.Errorf("a genuine undefined ALL_CAPS macro in the window must still flag MacroContext")
	}
}
