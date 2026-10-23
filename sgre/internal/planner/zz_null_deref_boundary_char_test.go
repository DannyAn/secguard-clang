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

// TestNullDeref_BoundaryFailOpenCharacterization pins the boundary-mode
// fail-open contract with the production shapes a MAF scan reported: with no
// `main` in the scan tree, a zero-call-site externally-callable function's
// parameter dereference surfaces as a suspected `null@caller-arg` candidate,
// and a field read of that parameter surfaces as a suspected
// `null@opaque-origin` candidate — both fail-open ASSUMPTIONS that stay
// suspected (never auto-confirmed) for the AI to judge. These rows ARE the
// boundary scan's product decision (see TestBoundaryScanExportedAPI): any
// future tier-level suppression must flip this characterization deliberately,
// not drift past it.
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
		for _, want := range []string{"proc", "proc->base", "proc->base.msg", "proc->base.msg->ctx", "proc->base.msg->ctx->conn"} {
			if !vars[want] {
				t.Errorf("field chain a->b->c->d: missing per-prefix candidate %q (got %v)", want, vars)
			}
		}
	})
}
