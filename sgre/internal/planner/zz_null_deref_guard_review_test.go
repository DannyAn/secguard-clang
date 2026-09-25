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

func planNullDerefGuardReview(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "guard_review.c")
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

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

func candidateLines(t *testing.T, result *PlanResult, fn string) []int {
	t.Helper()
	var lines []int
	for i := range result.Candidates {
		if result.Candidates[i].Target.Function == fn {
			lines = append(lines, result.Candidates[i].Target.Line)
		}
	}
	return lines
}

func hasLine(lines []int, want int) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

const guardReviewPreamble = `#include <stdlib.h>

typedef struct S { int x; int y; } S;
typedef struct node { int x; int y; struct node *next; } node_t;

node_t *get_node(void);
`

// D4: a `||` disjunction does not establish non-null for either operand, so the
// then-branch deref of p is a real null-deref and must stay flagged.
func TestNullDeref_GuardReview_OrCompound(t *testing.T) {
	src := guardReviewPreamble + `
void d4_or_guard(S *q) {
    S *p = NULL;
    if (p != NULL || q != NULL) {
        p->x = 1;
    }
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "d4_or_guard"); c == nil {
		t.Errorf("d4_or_guard should STAY flagged (|| does not prove p non-null)")
	}
}

// D5: a positive guard's non-null fact must not extend into the else branch,
// where the condition is negated (p is definitely NULL).
func TestNullDeref_GuardReview_ElseBranch(t *testing.T) {
	src := guardReviewPreamble + `
void d5_else(void) {
    S *p = NULL;
    if (p != NULL) {
        p->x = 1;
    } else {
        p->y = 2;
    }
}
`
	result := planNullDerefGuardReview(t, src)
	lines := candidateLines(t, result, "d5_else")
	if len(lines) == 0 {
		t.Fatalf("d5_else should flag the else-branch deref (p is NULL there)")
	}
	// The then-branch deref is guarded (non-null); only the else deref survives.
	for _, l := range lines {
		// p->x (then) is at line 6, p->y (else) at line 8 of the fixture body.
		if l == 6 {
			t.Errorf("d5_else then-branch deref at line %d should NOT be flagged (guarded)", l)
		}
	}
}

// D6: a null-guard nested inside a conditional only holds on that branch; the
// fall-through after the conditional must still flag the deref.
func TestNullDeref_GuardReview_NestedGuard(t *testing.T) {
	src := guardReviewPreamble + `
void d6_nested(int c) {
    S *p = NULL;
    if (c) {
        if (p == NULL) return;
    }
    p->x = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "d6_nested"); c == nil {
		t.Errorf("d6_nested should STAY flagged (the guard only holds when c is true)")
	}
}

// D7: `if (p == NULL) { p->x; }` establishes NULL (not non-null) in the branch,
// so the deref is a definite null-deref and must stay flagged.
func TestNullDeref_GuardReview_EqNullGuard(t *testing.T) {
	src := guardReviewPreamble + `
void d7_eqnull(void) {
    S *p = NULL;
    if (p == NULL) {
        p->x = 1;
    }
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "d7_eqnull"); c == nil {
		t.Errorf("d7_eqnull should STAY flagged (p == NULL in the branch)")
	}
}

// D8: a while-loop guard protects the WHOLE body on the taken branch, so every
// dereference inside — including the `p->next` read in the advance and the
// post-advance `p->y` — is guarded by `p != NULL`. The CFG guard kills p's null
// source on the loop body's entry edge, so nothing inside is flagged.
func TestNullDeref_GuardReview_WhileReassign(t *testing.T) {
	src := guardReviewPreamble + `
void d8_while(void) {
    node_t *p = get_node();
    while (p != NULL) {
        p->x = 1;
        p = p->next;
        p->y = 2;
    }
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "d8_while"); c != nil {
		t.Errorf("d8_while should NOT be flagged (whole loop body guarded by p != NULL), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// D11: a `&&` conjunction establishes non-null for EVERY operand, so the second
// operand's deref is guarded and must not be flagged.
func TestNullDeref_GuardReview_AndCompound(t *testing.T) {
	src := guardReviewPreamble + `
void d11_and(S *p) {
    S *q = NULL;
    if (p != NULL && q != NULL) {
        q->x = 1;
    }
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "d11_and"); c != nil {
		t.Errorf("d11_and should NOT be flagged (q is non-null via &&), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// A `&&` conjunction in an early-return guard does NOT establish either operand
// non-null on the fall-through (`!(p == NULL && q)` = `p != NULL || !q`), so the
// deref after it is still a real null-deref and must stay flagged.
func TestNullDeref_GuardReview_AndEarlyReturn(t *testing.T) {
	src := guardReviewPreamble + `
void d_and_return(int q) {
    S *p = NULL;
    if (p == NULL && q) { return; }
    p->x = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "d_and_return"); c == nil {
		t.Errorf("d_and_return should STAY flagged (p == NULL && q does not prove p non-null on fall-through)")
	}
}

// The same `&&` compound guard must not be misread by the caller-null detector:
// a caller `if (p == NULL && q) return; process(p);` still passes a possibly-null
// p, so process's parameter deref must surface.
func TestNullDeref_GuardReview_AndEarlyReturnInterprocedural(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct S { int x; } S;
S *get_p(void);
static void process(S *p) {
    p->x = 1;
}
void caller(int q) {
    S *p = get_p();
    if (p == NULL && q) { return; }
    process(p);
}
`
	result := planNullDerefGuardReviewFull(t, src)
	if c := candidateForFunc(t, result, "process"); c == nil {
		t.Errorf("process should STAY flagged (caller's p == NULL && q guard does not prove p non-null)")
	}
}

// D13: a parenthesized NULL literal (`(NULL)`) is still an explicit null source.
func TestNullDeref_GuardReview_ParenNullLiteral(t *testing.T) {
	src := guardReviewPreamble + `
void d13_paren_null(void) {
    S *q = (NULL);
    q->x = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	c := candidateForFunc(t, result, "d13_paren_null")
	if c == nil {
		t.Fatalf("d13_paren_null should STAY flagged (q = (NULL) is an explicit null)")
	}
	if !c.HasDefiniteNull {
		t.Errorf("d13_paren_null's q is explicitly nulled, expected has_definite_null=true")
	}
}

// planNullDerefGuardReviewFull runs the null-deref pipeline including the
// caller-null detector, for the inter-procedural D9/D10 cases.
func planNullDerefGuardReviewFull(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "guard_review_full.c")
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
	evidence.NewCallerNullDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// D9: a caller that passes a literal NULL makes the callee's parameter deref a
// DEFINITE null-deref, so it must be confirmed (not merely suspected).
func TestNullDeref_GuardReview_CallerNullDefinite(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct S { int x; } S;
static void process(S *p) {
    p->x = 1;
}
void caller(void) {
    process(NULL);
}
`
	result := planNullDerefGuardReviewFull(t, src)
	c := candidateForFunc(t, result, "process")
	if c == nil {
		t.Fatalf("process(NULL) must surface as a null-deref")
	}
	if !c.HasDefiniteNull {
		t.Errorf("process(NULL) should be a definite (confirmed) null-deref, got has_definite_null=%v level=%s", c.HasDefiniteNull, c.SuspicionLevel)
	}
}

// D10: an array argument is never NULL, so `process(buf)` must not seed a
// caller-null source and must not surface.
func TestNullDeref_GuardReview_ArrayArg(t *testing.T) {
	src := `#include <stdlib.h>
typedef struct S { int x; } S;
static void process(S *p) {
    p->x = 1;
}
void caller(void) {
    S buf[4];
    process(buf);
}
`
	result := planNullDerefGuardReviewFull(t, src)
	if c := candidateForFunc(t, result, "process"); c != nil {
		t.Errorf("process(buf) must NOT surface (buf is a non-nullable array), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}
