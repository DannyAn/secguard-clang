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

// planNullDerefMacro runs the full null-deref pipeline (index → graph → detectors
// → planner) on an inline source and returns the converged result. It is the
// shared harness for the macro-expansion regression matrix below.
func planNullDerefMacro(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "macro.c")
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
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

func candidateForFunc(t *testing.T, result *PlanResult, fn string) *EvidenceItem {
	t.Helper()
	for i := range result.Candidates {
		if result.Candidates[i].Target.Function == fn {
			return &result.Candidates[i]
		}
	}
	return nil
}

const macroLoopPreamble = `#include <stdlib.h>

typedef struct node { int value; struct node *next; } node_t;

#define LIST_FOR_EACH(iter, head) \
    for ((iter) = (head); (iter) != NULL; (iter) = (iter)->next) {

#define LIST_FOR_EACH_END }

#define DO_BLOCK_BEGIN do {
#define DO_BLOCK_END } while (0)

#define list_for_each(pos, head) \
    for ((pos) = (head); (pos) != NULL; (pos) = (pos)->next)
`

// ---------------------------------------------------------------------------
// Working patterns: the macro call site still preserves a READ dereference as a
// field_expression, so these are detected.
// ---------------------------------------------------------------------------

// TestNullDeref_TwoMacroLoopRead: two macros form a `for` loop (opening brace in
// one, closing brace in the other); a NULL source before the loop and a READ
// dereference inside it is detected and confirmed.
func TestNullDeref_TwoMacroLoopRead(t *testing.T) {
	src := macroLoopPreamble + `
static int count(node_t *head) {
    node_t *q = NULL;
    node_t *iter;
    int total = 0;
    LIST_FOR_EACH(iter, head)
        total += q->value;
    LIST_FOR_EACH_END
    return total;
}

int main(void) { return count((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "count")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in count(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed", c.SuspicionLevel)
	}
}

// TestNullDeref_MacroLoopReturn: a READ dereference inside a `return` placed in
// the flattened loop body is detected.
func TestNullDeref_MacroLoopReturn(t *testing.T) {
	src := macroLoopPreamble + `
static int ret(node_t *head) {
    node_t *q = NULL;
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        return q->value;
    LIST_FOR_EACH_END
    return 0;
}

int main(void) { return ret((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "ret")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in ret(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed", c.SuspicionLevel)
	}
}

// TestNullDeref_MacroLoopBreak: `break` inside the flattened loop is modelled as
// a function exit (BuildStmtCFG edges it to exit because no real loop exists),
// so the only path reaching the post-loop READ dereference is the branch where q
// is still NULL. Detection is correct (a real null-deref risk exists); the
// "confirmed" tier is a flattening artifact — a real loop would demote it to
// suspected. Pinned so a future loop-model change is a visible behavior change.
func TestNullDeref_MacroLoopBreak(t *testing.T) {
	src := macroLoopPreamble + `
static int brk(node_t *head) {
    node_t *q = NULL;
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        if (iter->value == 0) { q = iter; break; }
    LIST_FOR_EACH_END
    return q->value;
}

int main(void) { return brk((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "brk")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in brk(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed (flattened break → exit models q as definitely NULL)", c.SuspicionLevel)
	}
}

// TestNullDeref_MacroLoopSubscript: a WRITE subscript dereference (`q[0] = 1`)
// at the macro call site is parsed as a subscript_expression whose base is
// buried in an ERROR node; extractBaseOperand must recover `q`.
func TestNullDeref_MacroLoopSubscript(t *testing.T) {
	src := macroLoopPreamble + `
static int sub(node_t *head) {
    int *q = NULL;
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        q[0] = 1;
    LIST_FOR_EACH_END
    return 0;
}

int main(void) { return sub((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "sub")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in sub(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed", c.SuspicionLevel)
	}
}

// TestNullDeref_MacroLoopExplicitDeref: an explicit `*q = 1` WRITE dereference
// at the macro call site is parsed as binary_expression[*, call_expression,
// assignment_expression] (the `*` misread as multiplication);
// detectExplicitDerefInBinary must recover `q` from the assignment LHS.
func TestNullDeref_MacroLoopExplicitDeref(t *testing.T) {
	src := macroLoopPreamble + `
static int ptrw(node_t *head) {
    int *q = NULL;
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        *q = 1;
    LIST_FOR_EACH_END
    return 0;
}

int main(void) { return ptrw((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "ptrw")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in ptrw(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed", c.SuspicionLevel)
	}
}

// TestNullDeref_MacroLoop_NoFalsePositive guards the explicit-deref recovery:
// genuine multiplication `foo(a) * (b = 1)` (parenthesized RHS) and `a * b` must
// NOT be reinterpreted as a dereference.
func TestNullDeref_MacroLoop_NoFalsePositive(t *testing.T) {
	src := macroLoopPreamble + `
static int safe(node_t *head) {
    int *q = NULL;
    node_t *iter;
    int x = 0;
    LIST_FOR_EACH(iter, head)
        x = foo(1) * (q = 2);
    LIST_FOR_EACH_END
    return x;
}

int main(void) { return safe((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "safe"); c != nil {
		t.Errorf("safe() should NOT be flagged (parenthesized RHS is genuine multiplication, not a deref), got: %s", candidateNames(result))
	}
}

// TestNullDeref_IteratorSafe: dereferencing the loop iterator INSIDE the loop is
// safe (the `iter != NULL` condition guards the body), so no NULL source reaches
// it and it must NOT be flagged — even though the loop is flattened away.
func TestNullDeref_IteratorSafe(t *testing.T) {
	src := macroLoopPreamble + `
static int iter_safe(node_t *head) {
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        iter->value = 1;
    LIST_FOR_EACH_END
    return 0;
}

int main(void) { return iter_safe((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "iter_safe"); c != nil {
		t.Errorf("iter_safe() should NOT be flagged (iterator is non-NULL inside the loop), got: %s", candidateNames(result))
	}
}

// ---------------------------------------------------------------------------
// Macro call-site recovery: these shapes used to make tree-sitter recover with
// ERROR nodes that swallowed the `->` dereference and were silently missed. The
// dereference detector now recovers the pointer from the ERROR node (and from
// field_expression nodes whose base is buried in an ERROR), so all three are
// detected.
// ---------------------------------------------------------------------------

// TestNullDeref_MacroLoopWrite: a WRITE dereference (`q->value = 1`) at the
// macro call site is parsed as a field_expression whose base is buried in an
// ERROR node (the macro invocation is glued on as the call_expression operand).
// extractPointerFromField must recover `q` from that ERROR node.
func TestNullDeref_MacroLoopWrite(t *testing.T) {
	src := macroLoopPreamble + `
static int wr(node_t *head) {
    node_t *q = NULL;
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        q->value = 1;
    LIST_FOR_EACH_END
    return 0;
}

int main(void) { return wr((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "wr")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in wr(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed", c.SuspicionLevel)
	}
}

// TestNullDeref_BareMacroDoWhile: `do { } while(0)` split across two BARE
// (object-like) macros. The bare identifiers are parsed as a declaration's type
// name, and the body's `->` lands inside an ERROR node ("q->") with no
// field_expression at all — detectMemberAccessInErrors must recover it.
func TestNullDeref_BareMacroDoWhile(t *testing.T) {
	src := macroLoopPreamble + `
static int do_block(void) {
    node_t *q = NULL;
    DO_BLOCK_BEGIN
        q->value = 1;
    DO_BLOCK_END
    return 0;
}

int main(void) { return do_block(); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "do_block")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in do_block(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed", c.SuspicionLevel)
	}
}

// TestNullDeref_SingleMacroNoBraces: a single function-like macro that hides a
// brace-less `for` header (kernel `list_for_each` style). The body statement is
// folded into the call expression's ERROR recovery, so the pointer is recovered
// from the field_expression's ERROR child.
func TestNullDeref_SingleMacroNoBraces(t *testing.T) {
	src := macroLoopPreamble + `
static int single_macro(node_t *head) {
    node_t *q = NULL;
    node_t *pos;
    list_for_each(pos, head)
        q->value = 1;
    return 0;
}

int main(void) { return single_macro((node_t *)0); }
`
	result := planNullDerefMacro(t, src)
	c := candidateForFunc(t, result, "single_macro")
	if c == nil {
		t.Fatalf("expected a null-deref candidate in single_macro(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("Suspicion = %q, want confirmed", c.SuspicionLevel)
	}
}
