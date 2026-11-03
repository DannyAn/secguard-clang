//go:build !nosqlite

package planner

import (
	"context"
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

func planUninitOutputParam(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "outparam.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

const outParamPreamble = `#include <stdlib.h>

static int noop(int a) { return a; }

static int fill(int *out, int fail) {
    if (fail) {
        return -1;
    }
    *out = 1;
    return 0;
}
`

// TestUninit_OutputParamGuardFar pins the reported false positive: a conditional
// output-param writer (`fill` writes *out only on success) whose error guard sits
// several statements BELOW the call. The detector's guard scan previously used a
// hard-coded +2 line window and missed the guard, so the success-path use was
// misreported (then machine-confirmed) as uninit. The guard scan now has no line
// window, so the far guard is found and the success-path use is suppressed.
func TestUninit_OutputParamGuardFar(t *testing.T) {
	src := outParamPreamble + `
int guarded_far(int fail) {
    int x;
    int rc = fill(&x, fail);
    int a = noop(1);
    int b = noop(2);
    int c = noop(3);
    if (rc != 0) {
        return -1;
    }
    return x; /* success path: x is initialized */
}
`
	result := planUninitOutputParam(t, src)
	if c := candidateForFunc(t, result, "guarded_far"); c != nil {
		t.Errorf("guarded_far should NOT be flagged (x is written by fill on the success path, guarded far below the call), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// TestUninit_OutputParamGuardNearErrorBranch: the error branch reads x BEFORE the
// callee wrote it (the callee skips the write on failure), so it is a GENUINE
// uninitialized read and must stay reported.
func TestUninit_OutputParamGuardNearErrorBranch(t *testing.T) {
	src := outParamPreamble + `
int guarded_near(int fail) {
    int x;
    int rc = fill(&x, fail);
    if (rc != 0) {
        return x; /* genuine: x is uninit on the error path */
    }
    return x;
}
`
	result := planUninitOutputParam(t, src)
	if c := candidateForFunc(t, result, "guarded_near"); c == nil {
		t.Errorf("guarded_near must be flagged (x is uninit on the error path), got: %s", candidateNames(result))
	}
}

// TestUninit_OutputParamUnguarded: a conditional writer with NO error guard.
// The write-back idiom (`fn(&x)` assigning the caller's variable) is now
// trusted even without a caller-side error guard — production dogfooding
// showed the unguarded form floods reports with false positives, so the use
// after the call is suppressed. Error-path uses stay reported when the caller
// DOES guard (TestUninit_OutputParamGuardNearErrorBranch).
func TestUninit_OutputParamUnguarded(t *testing.T) {
	src := outParamPreamble + `
int unguarded(int fail) {
    int x;
    fill(&x, fail);
    return x; /* x is written by fill through &x on the success path */
}
`
	result := planUninitOutputParam(t, src)
	if c := candidateForFunc(t, result, "unguarded"); c != nil {
		t.Errorf("unguarded must NOT be flagged (fill(&x) is trusted as an out-param write-back), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// TestUninit_EvidenceCarriesDeclLine pins the declaration anchor in the uninit
// candidate evidence. A suspected uninit use can sit far below its declaration
// (outside the ±8 candidate Code Context window), so the classifier needs the
// declaration line in the Evidence to locate the (potential) initialization
// without guessing or widening the shared context window.
func TestUninit_EvidenceCarriesDeclLine(t *testing.T) {
	src := outParamPreamble + `
int plain_uninit(int fail) {
    int x;
    int y = fail + 1;
    return x + y; /* x is never written: genuine uninit read */
}
`
	result := planUninitOutputParam(t, src)
	c := candidateForFunc(t, result, "plain_uninit")
	if c == nil {
		t.Fatalf("plain_uninit must be flagged, got: %s", candidateNames(result))
	}
	for _, e := range c.Evidence {
		if e.Type == "declaration" && strings.Contains(e.Detail, "declared at line") {
			return
		}
	}
	t.Errorf("uninit evidence should carry a 'declared at line N' declaration anchor, got %+v", c.Evidence)
}

// TestUninit_EvidenceHeapUninitCarriesAllocLine pins the heap_uninit evidence
// anchor. A pointer declared on one line and malloc'd on another reports the
// malloc line as decl_line; calling that line "declared at" would mislabel the
// allocation site as the declaration, so the evidence says "allocated at line N".
// The fixture carries the interprocedural conditional-writer evidence: the
// planner pre-dismisses a bare `init@unseen` heap read (issue #200), so the
// allocation anchor is only observable on an evidenced heap candidate.
func TestUninit_EvidenceHeapUninitCarriesAllocLine(t *testing.T) {
	src := `#include <stdlib.h>

void heap_fill_cond(int *p, int fail, int v) {
    if (fail) {
        return;          /* error path leaves *p unwritten */
    }
    *p = v;
}

int heap_uninit(void) {
    int *p;
    p = (int *)malloc(sizeof(int));
    heap_fill_cond(p, 1, 7);   /* return discarded: conditional writer evidence */
    return *p;
}
`
	result := planUninitOutputParam(t, src)
	c := candidateForFunc(t, result, "heap_uninit")
	if c == nil {
		t.Fatalf("heap_uninit must be flagged, got: %s", candidateNames(result))
	}
	for _, e := range c.Evidence {
		if e.Type == "allocation" && strings.Contains(e.Detail, "allocated at line") {
			return
		}
	}
	t.Errorf("heap_uninit evidence should carry an 'allocated at line N' allocation anchor, got %+v", c.Evidence)
}

// TestUninit_ForwardedConditionalWriterKeepsHeapRead pins the issue #200
// escalation for the real interprocedural shape: a wrapper forwards the heap
// buffer to an in-scan writer only on the normal-data path and returns early
// otherwise, so the wrapper is a CONDITIONAL writer (summary propagation through
// forwarded calls). The caller discards the return and reads the buffer, which
// the weak-tier filter must keep with init@error-path/init-writer@ evidence
// instead of dismissing it as a bare init@unseen row.
func TestUninit_ForwardedConditionalWriterKeepsHeapRead(t *testing.T) {
	src := `#include <stdlib.h>

static void heap_write_all(int *p, int v) {
    *p = v;
}

static void heap_fill_forward(int *p, int kind, int v) {
    if (kind == 0) {
        return;             /* error path: the forwarded write never runs */
    }
    heap_write_all(p, v);   /* forwarded to an every-path writer */
}

int heap_forwarded(void) {
    int *p = (int *)malloc(sizeof(int));
    heap_fill_forward(p, 0, 7);   /* return discarded */
    return *p;
}
`
	result := planUninitOutputParam(t, src)
	c := candidateForFunc(t, result, "heap_forwarded")
	if c == nil {
		t.Fatalf("heap_forwarded (conditional forwarded writer, discarded return) must be flagged, got: %s", candidateNames(result))
	}
	if !strings.Contains(c.Hint, "init@error-path") || !strings.Contains(c.Hint, "init-writer@heap_fill_forward") {
		t.Errorf("heap_forwarded hint must carry init@error-path + init-writer@heap_fill_forward, got %q", c.Hint)
	}
}

// TestUninit_WeakTierDismissesHeapReads pins the default-dismiss half: a heap
// read with no conditional writer evidence (a bare allocator read, or a call to
// a writer that writes on every path) is the fail-open init@unseen tier and does
// not reach the AI.
func TestUninit_WeakTierDismissesHeapReads(t *testing.T) {
	src := `#include <stdlib.h>

static void heap_write_all(int *p, int v) {
    *p = v;
}

int heap_bare(void) {
    int *p = (int *)malloc(sizeof(int));
    return *p;
}

int heap_every_path_writer(void) {
    int *p = (int *)malloc(sizeof(int));
    heap_write_all(p, 7);
    return *p;
}
`
	result := planUninitOutputParam(t, src)
	for _, fn := range []string{"heap_bare", "heap_every_path_writer"} {
		if c := candidateForFunc(t, result, fn); c != nil {
			t.Errorf("%s: a heap read without conditional-writer evidence must be auto-dismissed, got hint %q", fn, c.Hint)
		}
	}
}
