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

func planDivideByZero(t *testing.T, src string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "dbz_review.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewDivideByZeroDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

// DBZ-01: float-typed operands make the division IEEE 754 float division, not an
// integer trap, so `double total / int count` must NOT be flagged.
func TestDivideByZeroReview_FloatOperand(t *testing.T) {
	src := `#include <stdlib.h>
double avg(int count) {
    double total = 0.0;
    return total / count;
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "avg"); c != nil {
		t.Errorf("avg (double / int) should NOT be flagged as CWE-369, got var=%s", c.Target.Variable)
	}
}

// DBZ-04: `if (d != 0 || x) { a/d; }` does NOT establish d non-zero on the taken
// branch, so the division must stay flagged.
func TestDivideByZeroReview_OrCompoundGuard(t *testing.T) {
	src := `#include <stdlib.h>
int f(int d, int x) {
    if (d != 0 || x) {
        return 10 / d;
    }
    return 0;
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "f"); c == nil {
		t.Errorf("f (d != 0 || x does not prove d non-zero) should be flagged")
	}
}

// DBZ-05: `if (ad != 0) { x / d; }` must NOT be read as guarding d (substring
// `d != 0` inside `ad != 0`).
func TestDivideByZeroReview_SubstringGuard(t *testing.T) {
	src := `#include <stdlib.h>
int f(int ad, int d) {
    if (ad != 0) {
        return 10 / d;
    }
    return 0;
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "f"); c == nil {
		t.Errorf("f (ad != 0 does not guard d) should be flagged")
	}
}

// DBZ-12: `if (d && x) { a/d; }` DOES establish d non-zero, so the division is
// guarded and must not be flagged.
func TestDivideByZeroReview_AndCompoundGuard(t *testing.T) {
	src := `#include <stdlib.h>
int f(int d, int x) {
    if (d && x) {
        return 10 / d;
    }
    return 0;
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "f"); c != nil {
		t.Errorf("f (d && x proves d non-zero) should NOT be flagged, got var=%s", c.Target.Variable)
	}
}

// DBZ-08: a compound assignment divisor `a /= b` must be detected.
func TestDivideByZeroReview_CompoundAssign(t *testing.T) {
	src := `#include <stdlib.h>
void f(int a, int b) {
    a /= b;
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "f"); c == nil {
		t.Errorf("f (a /= b) should be flagged as divide-by-zero")
	}
}

// DBZ-16: a function-like macro (`#define WORKERS() 8`) and an implicit
// enumerator (`enum { A, B }` → B=1) are compile-time non-zero constants and
// must not be flagged.
func TestDivideByZeroReview_ConstantSymbols(t *testing.T) {
	src := `#include <stdlib.h>
#define WORKERS() 8
enum { A, B };
int f(int x) {
    return x / WORKERS() + x / B;
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "f"); c != nil {
		t.Errorf("f (x / WORKERS(), x / B are non-zero constants) should NOT be flagged, got var=%s", c.Target.Variable)
	}
}

// DBZ-15: a constant-folded divisor (`d = 2 * 3`) is provably non-zero and must
// be suppressed.
func TestDivideByZeroReview_ConstFoldedDivisor(t *testing.T) {
	src := `#include <stdlib.h>
int f(int x) {
    int d = 2 * 3;
    return x / d;
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "f"); c != nil {
		t.Errorf("f (d = 2*3 is provably non-zero) should NOT be flagged, got var=%s", c.Target.Variable)
	}
}

// DBZ-01 (join semantics): a variable assigned zero on only one branch is not
// zero on every path. Before the merge treated an absent predecessor fact as
// equal to the other path, this false-confirmed the division.
func TestDivideByZeroReview_JoinAbsentPath(t *testing.T) {
	src := `#include <stdlib.h>
int f(int c) {
    int d;
    if (c) {
        d = 0;
    }
    return 10 / d;
}
`
	result := planDivideByZero(t, src)
	c := candidateForFunc(t, result, "f")
	if c == nil {
		t.Fatalf("f (d is only zero on one path) should stay a candidate, got none")
	}
	if c.SuspicionLevel == "confirmed" {
		t.Errorf("f should be suspected, not confirmed: d is not zero on every path")
	}
}

// DBZ-02 (if/else branch): a division in the alternative branch is guarded only
// when the condition establishes zero. `if (d != 0) {} else { x / d; }` leaves
// d == 0 on the division's path and must be flagged.
func TestDivideByZeroReview_IfElseAlternative(t *testing.T) {
	src := `#include <stdlib.h>
int f(int d) {
    if (d != 0) {
        return 1;
    } else {
        return 10 / d;
    }
}
`
	result := planDivideByZero(t, src)
	if c := candidateForFunc(t, result, "f"); c == nil {
		t.Errorf("f (division in else branch with d == 0) should be flagged")
	}
}
