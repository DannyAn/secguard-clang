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

// planUninitMacro runs the full uninit pipeline (index → graph → detector →
// planner) on an inline source and returns the converged result.
func planUninitMacro(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "uninit_macro.c")
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

const uninitMacroPreamble = `#include <stdlib.h>

typedef struct node { int value; struct node *next; } node_t;

#define LIST_FOR_EACH(iter, head) \
    for ((iter) = (head); (iter) != NULL; (iter) = (iter)->next) {

#define LIST_FOR_EACH_END }
`

// TestUninit_MacroLoopKillRecovered pins the false-positive fix: a variable
// assigned INSIDE a macro-formed loop (`q = 1`) must be recorded as initialized
// (the assignment LHS is buried in an ERROR node at the macro call site). Before
// assignmentLHSName recovered the LHS, the kill was missed and `return q` was
// wrongly reported "confirmed".
func TestUninit_MacroLoopKillRecovered(t *testing.T) {
	src := uninitMacroPreamble + `
static int a_kill(node_t *head) {
    int q;
    node_t *iter;
    LIST_FOR_EACH(iter, head)
        q = 1;
    LIST_FOR_EACH_END
    return q;
}

int main(void) { return a_kill((node_t *)0); }
`
	result := planUninitMacro(t, src)
	if c := candidateForFunc(t, result, "a_kill"); c != nil {
		t.Errorf("a_kill() should NOT be flagged (q is assigned inside the loop), got: %s", candidateNames(result))
	}
}

// TestUninit_MacroLoopReadRecovered pins the false-negative fix: a read of an
// uninitialized variable inside a macro-formed loop (`total += q`) must be
// reported. Before assignmentRHSStart shifted the RHS past the glued macro
// call + ERROR LHS, the `q` read was missed.
func TestUninit_MacroLoopReadRecovered(t *testing.T) {
	src := uninitMacroPreamble + `
static int b_read(node_t *head) {
    int q;
    node_t *iter;
    int total = 0;
    LIST_FOR_EACH(iter, head)
        total += q;
    LIST_FOR_EACH_END
    return total;
}

int main(void) { return b_read((node_t *)0); }
`
	result := planUninitMacro(t, src)
	c := candidateForFunc(t, result, "b_read")
	if c == nil {
		t.Fatalf("expected an uninit candidate in b_read(), got: %s", candidateNames(result))
	}
	if c.Target.Variable != "q" {
		t.Errorf("Variable = %q, want q", c.Target.Variable)
	}
}
