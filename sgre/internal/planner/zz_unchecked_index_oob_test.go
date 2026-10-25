//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Unchecked external index end-to-end: the production shape (a fixed-size
// struct array indexed by a field that arrives from configuration, with no
// bounds check at the access) must surface as ONE suspected out-of-bounds
// candidate carrying the chain facts, while the fixed form (a capacity check
// at the entry) and the ordinary parameter/loop shapes stay dark.
const uncheckedIndexE2EProduction = `#define MAF_RBL_SVR_CFG_COUNT 4

typedef struct {
    const char *domain;
    unsigned int code;
} maf_rbl_svr_cfg_t;

typedef struct maf_rbl_profile {
    unsigned int actived_index;
    maf_rbl_svr_cfg_t svr[MAF_RBL_SVR_CFG_COUNT];
} maf_rbl_profile_t;

int maf_show_dataplane_config_all_reply_code(const maf_rbl_svr_cfg_t *svr)
{
    if (strlen(svr->domain) == 0) {
        return -1;
    }
    return (int)svr->code;
}

int show_active(maf_rbl_profile_t *rbl_profile)
{
    unsigned int idx = rbl_profile->actived_index;
    const char *q = rbl_profile->svr[idx].domain;
    int rc = maf_show_dataplane_config_all_reply_code(&rbl_profile->svr[idx]);
    return q ? rc : -1;
}

int show_active_fix(struct maf_rbl_profile *p)
{
    if (p->actived_index >= MAF_RBL_SVR_CFG_COUNT) {
        return 1;
    }
    return (int)p->svr[p->actived_index].code;
}
`

// The fixed form alone (no vulnerable sibling) must produce no candidate.
const uncheckedIndexE2EFixed = `#define MAF_RBL_SVR_CFG_COUNT 4

typedef struct {
    const char *domain;
    unsigned int code;
} maf_rbl_svr_cfg_t;

typedef struct maf_rbl_profile {
    unsigned int actived_index;
    maf_rbl_svr_cfg_t svr[MAF_RBL_SVR_CFG_COUNT];
} maf_rbl_profile_t;

int show_active_fixed(struct maf_rbl_profile *p)
{
    if (p->actived_index >= MAF_RBL_SVR_CFG_COUNT) {
        return 1;
    }
    return (int)p->svr[p->actived_index].code;
}
`

// Ordinary shapes: a caller-supplied index (parameter) and a loop variable are
// NOT field-derived, so the heuristic channel must not flood on them.
const uncheckedIndexE2EControl = `typedef struct {
    unsigned int n;
    int counters[8];
} Ctl_t;

void store_param(Ctl_t *c, unsigned int n)
{
    c->counters[n] = 1;
}

void loop_counters(Ctl_t *c, int limit)
{
    for (int i = 0; i < limit; i++) {
        c->counters[i] = i;
    }
}

void const_store(Ctl_t *c)
{
    c->counters[0] = 7;
}
`

// The write flavor routes to buffer-overflow (CWE-787).
const uncheckedIndexE2EWrite = `typedef struct {
    unsigned int slot;
    int counters[4];
} Wr_t;

void store_slot(Wr_t *w)
{
    w->counters[w->slot] = 9;
}
`

func runUncheckedIndexPlan(t *testing.T, files map[string]string, vulnType string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	var paths []string
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
		paths = append(paths, path)
	}
	idx := indexer.NewIndexer(store, logger)
	for _, path := range paths {
		if _, err := idx.Index(ctx, path); err != nil {
			t.Fatalf("index %s: %v", path, err)
		}
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, vulnType)
	if err != nil {
		t.Fatalf("plan %s: %v", vulnType, err)
	}
	return result
}

func TestUncheckedIndexOutOfBoundsEndToEnd(t *testing.T) {
	r := runUncheckedIndexPlan(t, map[string]string{"rbl.c": uncheckedIndexE2EProduction}, "out-of-bounds")
	if len(r.Candidates) != 1 {
		t.Fatalf("want exactly 1 out-of-bounds candidate for the production shape, got %d: %+v", len(r.Candidates), r.Candidates)
	}
	c := r.Candidates[0]
	if c.Target.Function != "show_active" {
		t.Errorf("function = %s, want show_active (the fixed sibling must stay silent)", c.Target.Function)
	}
	if c.SuspicionLevel != "suspected" {
		t.Errorf("suspicion = %s, want suspected (an unvalidated index is a heuristic, not a proof)", c.SuspicionLevel)
	}
	if c.Category != "array_oob_read_unchecked" {
		t.Errorf("category = %s, want array_oob_read_unchecked", c.Category)
	}
	if c.CWEChain != "CWE-125 → CWE-476" {
		t.Errorf("cwe_chain = %q, want the root-cause chain (one finding, consequence CWE as metadata)", c.CWEChain)
	}
	for _, token := range []string{"cap@4", "idx-src@actived_index", "elem-field@domain", "oob-escape@maf_show_dataplane_config_all_reply_code", "cwe-chain@CWE-125→CWE-476"} {
		if !strings.Contains(c.Hint, token) {
			t.Errorf("hint %q missing %s (the chain must be settleable from the index row)", c.Hint, token)
		}
	}
	var haveElemField, haveEscape bool
	for _, f := range c.VerdictFacts {
		if strings.HasPrefix(f.Token, "elem-field@domain") {
			haveElemField = true
		}
		if strings.HasPrefix(f.Token, "oob-escape@maf_show_dataplane_config_all_reply_code") {
			haveEscape = true
			if !strings.Contains(f.Detail, "domain") {
				t.Errorf("escape fact must name the dereferenced pointer member: %q", f.Detail)
			}
		}
	}
	if !haveElemField || !haveEscape {
		t.Errorf("verdict facts must carry the CWE-125 → CWE-476 chain (elem-field + escape); got %+v", c.VerdictFacts)
	}
}

func TestUncheckedIndexGuardedEndToEnd(t *testing.T) {
	r := runUncheckedIndexPlan(t, map[string]string{"rbl_fix.c": uncheckedIndexE2EFixed}, "out-of-bounds")
	if len(r.Candidates) != 0 {
		t.Fatalf("the fixed form (capacity check at the entry) must yield no candidate, got %+v", r.Candidates)
	}
}

func TestUncheckedIndexOrdinaryShapesEndToEnd(t *testing.T) {
	r := runUncheckedIndexPlan(t, map[string]string{"ctl.c": uncheckedIndexE2EControl}, "out-of-bounds")
	if len(r.Candidates) != 0 {
		t.Fatalf("parameter/loop/constant indices must not seed the unchecked-index channel, got %+v", r.Candidates)
	}
	r = runUncheckedIndexPlan(t, map[string]string{"ctl.c": uncheckedIndexE2EControl}, "buffer-overflow")
	if len(r.Candidates) != 0 {
		t.Fatalf("parameter/loop/constant write indices must not seed either, got %+v", r.Candidates)
	}
}

func TestUncheckedIndexWriteRoutesToBufferOverflow(t *testing.T) {
	r := runUncheckedIndexPlan(t, map[string]string{"wr.c": uncheckedIndexE2EWrite}, "buffer-overflow")
	if len(r.Candidates) != 1 {
		t.Fatalf("want 1 buffer-overflow candidate for the write flavor, got %d: %+v", len(r.Candidates), r.Candidates)
	}
	c := r.Candidates[0]
	if c.Category != "array_oob_write_unchecked" {
		t.Errorf("category = %s, want array_oob_write_unchecked", c.Category)
	}
	if c.SuspicionLevel != "suspected" {
		t.Errorf("suspicion = %s, want suspected", c.SuspicionLevel)
	}
	if !strings.Contains(c.Hint, "idx-src@slot") {
		t.Errorf("hint %q missing idx-src@slot", c.Hint)
	}
	// A scalar element write has no pointer-member read and no escape, so it
	// carries no CWE-476 consequence: the chain token only appears when the
	// element yields an indeterminate pointer (elem-field@ / oob-escape@).
	if c.CWEChain != "" {
		t.Errorf("scalar element write cwe_chain = %q, want empty (no pointer leg)", c.CWEChain)
	}
	// The read flavor must not see the write event.
	r = runUncheckedIndexPlan(t, map[string]string{"wr.c": uncheckedIndexE2EWrite}, "out-of-bounds")
	if len(r.Candidates) != 0 {
		t.Fatalf("the write flavor must not route to out-of-bounds, got %+v", r.Candidates)
	}
}
