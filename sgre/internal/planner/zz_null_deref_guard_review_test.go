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

// NP-03: a branch-hint-wrapped helper guard `if (unlikely(is_empty(p)))
// return;` must protect the fall-through dereference — helperGuard only
// unwrapped paren/cast, so the hint made the whole helper shape invisible.
func TestNullDeref_GuardReview_BranchHintWrappedHelper(t *testing.T) {
	src := guardReviewPreamble + `
int is_empty(S *p) { return p == NULL; }

void hint_helper(void) {
    S *p = malloc(sizeof(S));
    if (unlikely(is_empty(p))) {
        return;
    }
    p->x = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "hint_helper"); c != nil {
		t.Errorf("hint_helper p->x must NOT be flagged (unlikely(is_empty(p)) return guards the fall-through), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// NP-03 sibling: the comparison form `if (likely(check(p) == 0))` (hint
// wrapping the whole == condition) must also resolve the helper.
func TestNullDeref_GuardReview_BranchHintWrappedHelperComparison(t *testing.T) {
	src := guardReviewPreamble + `
int check(S *p) { if (p == NULL) return -1; return 0; }

void hint_helper_cmp(void) {
    S *p = malloc(sizeof(S));
    if (likely(check(p) == 0)) {
        p->x = 1;
    }
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "hint_helper_cmp"); c != nil {
		t.Errorf("hint_helper_cmp p->x must NOT be flagged (likely(check(p) == 0) proves p non-null on the true branch), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// NP-02: a switch whose condition is a (cast) pointer and whose `case 0` /
// `case NULL` branch RETURNS is a null guard for the fall-through: after
// `switch ((intptr_t)p) { case 0: return; default: break; }`, p is non-null.
func TestNullDeref_GuardReview_SwitchNullCaseReturn(t *testing.T) {
	src := guardReviewPreamble + `
void sw_guard(void) {
    S *p = malloc(sizeof(S));
    switch ((intptr_t)p) {
    case 0:
        return;
    default:
        break;
    }
    p->x = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "sw_guard"); c != nil {
		t.Errorf("sw_guard p->x must NOT be flagged (switch null-case-return guards the fall-through), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// NP-02 sibling: a `case 0: break;` does NOT exit — p stays nullable on the
// fall-through, and the dereference must STAY flagged.
func TestNullDeref_GuardReview_SwitchNullCaseBreak(t *testing.T) {
	src := guardReviewPreamble + `
void sw_no_guard(void) {
    S *p = malloc(sizeof(S));
    switch ((intptr_t)p) {
    case 0:
        break;
    default:
        break;
    }
    p->x = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "sw_no_guard"); c == nil {
		t.Errorf("sw_no_guard p->x must STAY flagged (case 0: break; does not exit — p stays nullable)")
	}
}

// ND-04: a cast guard `if ((S*)q != NULL)` must protect the dereference of q —
// the guarded-variable key is extracted structurally (not by trimming the
// operand text, which produced the garbage name `"S*)q"`).
func TestNullDeref_GuardReview_CastGuard(t *testing.T) {
	src := guardReviewPreamble + `
void cast_guard(void) {
    S *q = malloc(sizeof(S));
    if ((S*)q != NULL) {
        q->x = 1;
    }
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "cast_guard"); c != nil {
		t.Errorf("cast_guard q->x must NOT be flagged (cast guard (S*)q != NULL protects it), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// D8: a while-loop guard protects only the value it TESTED at the loop head.
// `p->x` before the advance is guarded; `p->y` AFTER `p = p->next` dereferences
// the NEW value — an open-world field read that can be NULL on the last hop.
// The guard says nothing about that new value, so `p->y` must STAY flagged.
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
	// The variable-level converge merges p's dereferences into one candidate
	// whose DerefLines lists every sink; assert on the sink list.
	for _, c := range result.Candidates {
		if c.Target.Function != "d8_while" || c.Target.Variable != "p" {
			continue
		}
		for _, dl := range c.DerefLines {
			if dl == 11 {
				t.Errorf("d8_while p->x (line 11) must NOT be flagged (guard protects the value tested at the loop head), got DerefLines=%v", c.DerefLines)
			}
		}
	}
	found := false
	for _, c := range result.Candidates {
		if c.Target.Function != "d8_while" || c.Target.Variable != "p" {
			continue
		}
		for _, dl := range c.DerefLines {
			if dl == 13 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("d8_while p->y (line 13, after `p = p->next`) must STAY flagged (the guard tested the OLD value; the new value is an open-world field read)")
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

// ND-01: explicit dereference operands wrapped in a cast or a post-increment
// must still resolve to the base pointer, or the null source key never matches
// and the null-deref is silently dropped.
func TestNullDeref_GuardReview_ExplicitDerefShapes(t *testing.T) {
	src := guardReviewPreamble + `
void nd_cast_deref(void) {
    void *p = NULL;
    *(int *)p = 0;
}

void nd_update_deref(void) {
    int *p = NULL;
    *p++ = 0;
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "nd_cast_deref"); c == nil {
		t.Errorf("nd_cast_deref should be flagged (*(int *)p with p == NULL)")
	}
	if c := candidateForFunc(t, result, "nd_update_deref"); c == nil {
		t.Errorf("nd_update_deref should be flagged (*p++ with p == NULL)")
	}
}

// ND-05: a pointer-typed cast of NULL/0 is a definite null source, not a kill
// of the previous may-source. Without this, `p = (S *)NULL; p->x;` was missed.
func TestNullDeref_GuardReview_CastNullAssignment(t *testing.T) {
	src := guardReviewPreamble + `
void nd_cast_null(void) {
    S *p = get_node();
    p = (S *)NULL;
    p->x = 1;
}

void nd_cast_zero(void) {
    S *p = get_node();
    p = (S *)0;
    p->x = 1;
}
`
	result := planNullDerefGuardReview(t, src)
	if c := candidateForFunc(t, result, "nd_cast_null"); c == nil {
		t.Errorf("nd_cast_null should be flagged (p = (S *)NULL)")
	}
	if c := candidateForFunc(t, result, "nd_cast_zero"); c == nil {
		t.Errorf("nd_cast_zero should be flagged (p = (S *)0)")
	}
}

// The same `&&` compound guard must not be misread as a proof of non-nullness.
// Since the caller argument is still only "not proven non-null", R1 converges it
// before AI; process must no longer surface.
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
	if c := candidateForFunc(t, result, "process"); c != nil {
		t.Errorf("process should be converged before AI (caller argument is only not-proven-null), got %s", c.Target.Function)
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
