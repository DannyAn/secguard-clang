//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// planNullDerefFullSrc runs the COMPLETE detector registry (the CLI pipeline's
// detector set, including CallerNullDetector and OpaqueNullDetector) before
// planning null-deref — the lean planNullDerefSrc helper covers only the four
// core detectors, which silently misses the boundary fail-open seeding the
// production boundary mode depends on.
func planNullDerefFullSrc(t *testing.T, src string) *PlanResult {
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
	evidence.RunAllDetectors(ctx, store, p, logger)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// TestNullDeref_BoundaryFailOpenCharacterization pins the "off" mode of the
// boundary fail-open contract (the recall-maximal escape hatch, set by this
// package's TestMain): with no `main` in the scan tree and
// boundary_auto_dismiss="off", a zero-call-site externally-callable function's
// parameter dereference surfaces as a suspected `null@caller-arg` candidate,
// and a field read of that parameter surfaces as a suspected
// `null@opaque-origin` candidate — both fail-open ASSUMPTIONS that stay
// suspected (never auto-confirmed) for the AI to judge. The NEW production
// default ("external") pre-dismisses these rows; see
// TestNullDeref_BoundaryFailOpenDefaultDismisses. Any future tier-level
// suppression must flip that test deliberately, not drift past it.
func TestNullDeref_BoundaryFailOpenCharacterization(t *testing.T) {
	t.Run("boundary-param-failopen", func(t *testing.T) {
		src := `struct ase_hash_key { const char *data; unsigned len; };

unsigned int maf_address_hash_func(const struct ase_hash_key *key)
{
    char *address = key->data;
    unsigned ret = 1;
    for (unsigned i = 0; i != key->len; ++i) {
        ret *= address[i];
    }
    return ret;
}
`
		res := planNullDerefFullSrc(t, src)
		tiers := map[string]string{}
		for _, c := range res.Candidates {
			tiers[c.Target.Variable] = c.NullOriginTier
			if c.SuspicionLevel != "suspected" {
				t.Errorf("boundary fail-open candidate %s: suspicion = %q, want suspected (never auto-confirmed)",
					c.Target.Variable, c.SuspicionLevel)
			}
		}
		if tiers["key"] != "caller-arg" {
			t.Errorf("zero-call-site externally-callable param deref: tier = %q, want caller-arg", tiers["key"])
		}
		if tiers["address"] != "opaque-origin" {
			t.Errorf("field-read of the open param: tier = %q, want opaque-origin", tiers["address"])
		}
	})

	t.Run("field-chain-per-deref-candidates", func(t *testing.T) {
		src := `struct conn { int conn_key; };
struct ctx { struct conn *conn; };
struct msg { struct ctx *ctx; };
struct base { struct msg *msg; };
struct proc { struct base base; };

int mail_rate_statistics_proc(struct proc *proc, int profile_id)
{
    return maf_rate_exceeded_query(profile_id, &proc->base.msg->ctx->conn->conn_key);
}

int maf_rate_exceeded_query(int profile_id, int *key) { return *key; }
`
		res := planNullDerefFullSrc(t, src)
		vars := map[string]bool{}
		for _, c := range res.Candidates {
			vars[c.Target.Variable] = true
			if c.SuspicionLevel != "suspected" {
				t.Errorf("field-chain candidate %s: suspicion = %q, want suspected", c.Target.Variable, c.SuspicionLevel)
			}
		}
		// One candidate per POINTER dereference in the chain. `proc->base` is a
		// `.` step selecting a struct VALUE member (`struct base base`), not a
		// pointer dereference — it can never be NULL and its fix suggestion
		// (`if (proc->base == NULL)`) would not even compile, so it must not be
		// a candidate. Every `->` step still gets one.
		for _, want := range []string{"proc", "proc->base.msg", "proc->base.msg->ctx", "proc->base.msg->ctx->conn"} {
			if !vars[want] {
				t.Errorf("field chain a->b->c->d: missing per-deref candidate %q (got %v)", want, vars)
			}
		}
		if vars["proc->base"] {
			t.Errorf("proc->base selects a struct value member, not a pointer: it must not be a candidate (got %v)", vars)
		}
	})
}

// TestNullDeref_BoundaryFailOpenDefaultDismisses pins the NEW production default
// ("external"): a boundary scan with no `main` pre-dismisses the fail-open
// ASSUMPTION tiers (caller-arg rooted at an unguarded external entry, and the
// opaque field read) into the boundary_fail_open ledger instead of surfacing
// them as suspected candidates for the AI. This is the recall-safe-by-ledger
// counterpart of TestNullDeref_BoundaryFailOpenCharacterization (which pins the
// "off" escape hatch).
func TestNullDeref_BoundaryFailOpenDefaultDismisses(t *testing.T) {
	t.Cleanup(func() { config.SetBoundaryAutoDismissOverride("off") })
	config.SetBoundaryAutoDismissOverride("") // fall back to the production default ("external")

	src := `struct ase_hash_key { const char *data; unsigned len; };

unsigned int maf_address_hash_func(const struct ase_hash_key *key)
{
    char *address = key->data;
    unsigned ret = 1;
    for (unsigned i = 0; i != key->len; ++i) {
        ret *= address[i];
    }
    return ret;
}
`
	res := planNullDerefFullSrc(t, src)
	if len(res.Candidates) != 0 {
		t.Fatalf("default boundary scan must pre-dismiss fail-open assumptions, got candidates %+v", res.Candidates)
	}
	// Three fail-open rows pre-convergence: `key` is dereferenced at key->data
	// and key->len (two caller-arg root candidates) and `address` is the opaque
	// field read. All three are pre-dismissed into the ledger.
	if n := res.Summary.DroppedByReason["boundary_fail_open"]; n != 3 {
		t.Fatalf("boundary_fail_open dismissed = %d, want 3 (key@5 + key@7 caller-arg root + address@8 opaque-origin); dropped = %+v", n, res.Summary.Dropped)
	}
}

// TestNullDeref_BoundaryCallbackChainDismisses pins the issue #215 framework
// callback-contract cut: a static function registered through a function pointer
// (ADDR_TAKEN) is a registration contract, and every forwarding hop whose chain
// ROOT is such a registration is graded callback-entry (not caller-arg), so the
// default boundary scan dismisses the whole chain instead of keeping one
// "judgeable" caller-arg row per forwarding level. The control keeps the
// deliberate recall trade-off: a forwarding chain rooted at a plain zero-call-site
// external entry is still caller-arg and reaches the AI in "external" mode.
func TestNullDeref_BoundaryCallbackChainDismisses(t *testing.T) {
	t.Cleanup(func() { config.SetBoundaryAutoDismissOverride("off") })
	config.SetBoundaryAutoDismissOverride("") // production default ("external")

	t.Run("callback-rooted chain dismissed", func(t *testing.T) {
		src := `struct cb_ctx { int n; };
typedef int (*cb_t)(struct cb_ctx *);
static int cb_leaf(struct cb_ctx *ctx) { return ctx->n; }
static int cb_dispatch(struct cb_ctx *ctx) { return cb_leaf(ctx); }
static cb_t g_cb = cb_dispatch;
void cb_install(void) { g_cb = cb_dispatch; }
`
		res := planNullDerefFullSrc(t, src)
		if len(res.Candidates) != 0 {
			t.Fatalf("callback-rooted forwarding chain must be pre-dismissed, got %+v", res.Candidates)
		}
		if n := res.Summary.DroppedByReason["boundary_fail_open"]; n == 0 {
			t.Fatalf("callback chain dismissal must be ledgered, dropped = %+v", res.Summary.Dropped)
		}
	})

	t.Run("plain external-entry chain kept", func(t *testing.T) {
		src := `struct api_ctx { int n; };
static int api_leaf(struct api_ctx *ctx) { return ctx->n; }
int api_entry(struct api_ctx *ctx) { return api_leaf(ctx); }
`
		res := planNullDerefFullSrc(t, src)
		if len(res.Candidates) != 1 {
			t.Fatalf("plain external-entry forwarding chain must stay for AI judgment, got %+v", res.Candidates)
		}
		c := res.Candidates[0]
		if c.NullOriginTier != "caller-arg" || c.ChainKind != "hop" {
			t.Errorf("external-entry chain tier = %q/%q, want caller-arg/hop", c.NullOriginTier, c.ChainKind)
		}
	})
}

// TestNullDeref_BoundaryOpaqueSourceWithInTreeCallerDismissed pins the issue
// #215 source-tier rule: an in-tree caller of the candidate function does not
// discharge a non-proving SOURCE tier. An opaque field read (`o->p` of an
// externally-defined struct) stays dismissed even though the function has an
// in-tree caller, while the caller-argument row for the same dereference chain
// remains the judgeable one.
func TestNullDeref_BoundaryOpaqueSourceWithInTreeCallerDismissed(t *testing.T) {
	t.Cleanup(func() { config.SetBoundaryAutoDismissOverride("off") })
	config.SetBoundaryAutoDismissOverride("")

	src := `struct opaque_s;
int opaque_use(struct opaque_s *o) { return o->p->n; }
int opaque_caller(struct opaque_s *o) { return opaque_use(o); }
`
	res := planNullDerefFullSrc(t, src)
	for _, c := range res.Candidates {
		if c.NullOriginTier == "opaque-origin" {
			t.Fatalf("opaque-origin source with an in-tree caller must be dismissed (an in-tree caller does not prove the field non-null), got %+v", c)
		}
	}
	var ledgered bool
	for _, d := range res.Summary.Dropped {
		if d.Filter == "boundary_fail_open" && d.VariableName == "o->p" {
			ledgered = true
		}
	}
	if !ledgered {
		t.Errorf("opaque-origin dismissal must stay visible in the boundary_fail_open ledger, dropped = %+v", res.Summary.Dropped)
	}
}
