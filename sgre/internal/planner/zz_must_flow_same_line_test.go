//go:build !nosqlite

package planner

import (
	"context"
	"io"
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

// planTempFixture indexes a one-file fixture, runs the given detector, and plans
// one vulnerability type. The same-line tests below need a real CFG, so they
// cannot use the planner's pure unit helpers.
func planTempFixture(t *testing.T, src, vulnType string, detect func(context.Context, db.Store, *parser.Parser, *log.Logger)) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := graph.NewCallGraphBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("call graph: %v", err)
	}
	if _, err := graph.NewDataFlowBuilder(store, p, logger).Build(ctx); err != nil {
		t.Fatalf("data flow: %v", err)
	}
	detect(ctx, store, p, logger)
	res, err := NewPlanner(store, p, logger).Plan(ctx, vulnType)
	if err != nil {
		t.Fatalf("plan %s: %v", vulnType, err)
	}
	return res
}

func candidateOf(res *PlanResult, function string) *EvidenceItem {
	for i := range res.Candidates {
		if res.Candidates[i].Target.Function == function {
			return &res.Candidates[i]
		}
	}
	return nil
}

// Issue #253 P2-1: `if (c) { free(p); } p->v = 1;` frees p on ONE branch, so a
// use-after-free is only possible, not certain. The line-keyed freed-state gen
// used to leak onto the same-line dereference node, and mustReachingAt counted
// the sink's own gen, auto-confirming a may-UAF. The unconditional control on
// the next line stays confirmed.
func TestMustFlow_SameLineConditionalFreeIsNotUAF(t *testing.T) {
	res := planTempFixture(t, `#include <stdlib.h>
typedef struct node { int v; struct node *next; } node_t;

void uaf_after_cond_free(int c, node_t *p)
{
    if (c) { free(p); } p->v = 1;
}

void real_uaf(node_t *p)
{
    free(p);
    p->v = 2;
}

void real_uaf_same_line(node_t *p) { free(p); p->v = 3; }
`, "use-after-free", func(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) {
		evidence.NewUseAfterFreeDetector(store, p, logger).Detect(ctx)
	})
	cond := candidateOf(res, "uaf_after_cond_free")
	if cond == nil {
		t.Fatalf("the conditional-free candidate must stay a lead, got %v", candidateNames(res))
	}
	if cond.SuspicionLevel == "confirmed" {
		t.Errorf("a free on one branch must not auto-confirm UAF at the same-line dereference (hint=%v)", cond.Hint)
	}
	for _, fn := range []string{"real_uaf", "real_uaf_same_line"} {
		control := candidateOf(res, fn)
		if control == nil || control.SuspicionLevel != "confirmed" {
			t.Errorf("%s: the unconditional free->use control must stay confirmed, got %+v", fn, control)
		}
	}
}

// Issue #253 P2-1: `if (c) { x = 1; } sink(x);` initializes x on ONE branch.
// The same line-keyed leak made the sink resolve to the assignment node and
// auto-confirmed a certain-uninit. The unconditional control stays confirmed.
func TestMustFlow_SameLineConditionalInitIsNotCertainUninit(t *testing.T) {
	res := planTempFixture(t, `int sink(int);

void uninit_after_cond_init(int c)
{
    int x;
    if (c) { x = 1; } sink(x);
}

void real_uninit(void)
{
    int y;
    sink(y);
}
`, "uninit", func(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) {
		evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx)
	})
	cond := candidateOf(res, "uninit_after_cond_init")
	if cond == nil {
		t.Fatalf("the conditional-init candidate must stay a lead, got %v", candidateNames(res))
	}
	if cond.SuspicionLevel == "confirmed" {
		t.Errorf("an initialization on one branch must not auto-confirm uninit at the same-line use (hint=%v)", cond.Hint)
	}
	control := candidateOf(res, "real_uninit")
	if control == nil || control.SuspicionLevel != "confirmed" {
		t.Errorf("the never-written control must stay confirmed, got %+v", control)
	}
}

// Issue #253 P2-1: `if (c) { free(p); } free(p);` is a double-free only when
// the branch was taken. The sink's own gen (the second free) must not be used
// as the must premise; the two-line control stays confirmed.
func TestMustFlow_SameLineConditionalFreeIsNotDoubleFree(t *testing.T) {
	res := planTempFixture(t, `#include <stdlib.h>

void df_after_cond_free(int c, char *p)
{
    if (c) { free(p); } free(p);
}

void real_df(char *p)
{
    free(p);
    free(p);
}

void real_df_same_line(char *p) { free(p); free(p); }
`, "double-free", func(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) {
		evidence.NewDoubleFreeDetector(store, p, logger).Detect(ctx)
	})
	cond := candidateOf(res, "df_after_cond_free")
	if cond == nil {
		t.Fatalf("the conditional-free double-free candidate must stay a lead, got %v", candidateNames(res))
	}
	if cond.SuspicionLevel == "confirmed" {
		t.Errorf("a conditional first free must not auto-confirm the same-line second free (hint=%v)", cond.Hint)
	}
	for _, fn := range []string{"real_df", "real_df_same_line"} {
		control := candidateOf(res, fn)
		if control == nil || control.SuspicionLevel != "confirmed" {
			t.Errorf("%s: the unconditional double-free control must stay confirmed, got %+v", fn, control)
		}
	}
}
