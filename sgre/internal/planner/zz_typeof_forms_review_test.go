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

// indexTypeofSrc indexes one in-memory source file, builds the call/data-flow
// graph, and runs the null-deref + unchecked-return detectors — the minimum
// pipeline the typeof-form regression tests need. It returns the store and a
// planner the test plans specific vuln types from.
func indexTypeofSrc(t *testing.T, src string) (db.Store, *Planner) {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(t.TempDir(), "typeof_forms.c")
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
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewUncheckedReturnDetector(store, p, logger).Detect(ctx)
	return store, NewPlanner(store, p, logger)
}

// TestTypeofForms_DetectionResults covers scenarios 5 and 7 of the regression
// plan:
//   - `typeof(*p) *v = malloc(n)` with a null check must NOT surface as an
//     unchecked-return (the typeof rewrite must preserve the assignment→check
//     chain), while an unguarded malloc in the same file still does;
//   - a real definite null-deref in the SAME file must still be reported and
//     confirmed — the typeof rewrite must not hide genuine defects.
func TestTypeofForms_DetectionResults(t *testing.T) {
	src := `#include <stdlib.h>

int *p;

typeof(*p) x;
typeof(p + 1) y;
typeof(int *) z;

void *allocate(size_t n)
{
    typeof(*p) *v = malloc(n);
    if (v == NULL)
        return NULL;
    return v;
}

void positive_unchecked(void)
{
    char *w = malloc(100);
    w[0] = 'x';
}

int real_null_deref(void)
{
    int *q = NULL;
    return *q;
}
`
	ctx := context.Background()
	_, pl := indexTypeofSrc(t, src)

	ur, err := pl.Plan(ctx, "unchecked-return")
	if err != nil {
		t.Fatalf("plan unchecked-return: %v", err)
	}
	urByFunc := map[string]bool{}
	for _, c := range ur.Candidates {
		urByFunc[c.Target.Function] = true
	}
	if urByFunc["allocate"] {
		t.Error("FALSE POSITIVE: null-checked typeof(*p) *v = malloc(n) flagged as unchecked-return")
	}
	if !urByFunc["positive_unchecked"] {
		t.Error("positive control: unguarded malloc should be flagged as unchecked-return")
	}

	nd, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}
	found := false
	for _, c := range nd.Candidates {
		if c.Target.Function == "real_null_deref" {
			found = true
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("real_null_deref must stay confirmed despite typeof coexisting, got %q", c.SuspicionLevel)
			}
		}
	}
	if !found {
		t.Error("real_null_deref was not reported (typeof rewrite hid a real defect)")
	}
}

// TestTypeofForms_QualityGateInvalidSyntax covers scenario 8: a file with a
// deliberately-broken construct must be MARKED (HasError) rather than silently
// accepted, but the indexer must still index the intact sibling function — the
// gate must not simply reject the whole file and hide its real findings.
func TestTypeofForms_QualityGateInvalidSyntax(t *testing.T) {
	src := `#include <stdlib.h>

int broken(void) { int x = ; }

int intact(void)
{
    int *q = NULL;
    return *q;
}
`
	// The gate marks the anomaly: the parse carries ERROR nodes.
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "broken.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tree.HasError() {
		t.Error("expected HasError() = true for the deliberately-broken construct")
	}
	tree.Close()

	// But indexing is best-effort: the intact function is still indexed and its
	// real null-deref still confirmed, so a broken sibling does not blank the file.
	ctx := context.Background()
	_, pl := indexTypeofSrc(t, src)
	nd, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}
	found := false
	for _, c := range nd.Candidates {
		if c.Target.Function == "intact" {
			found = true
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("intact should be confirmed, got %q", c.SuspicionLevel)
			}
		}
	}
	if !found {
		t.Error("intact function was not indexed/reported (quality gate rejected the whole file)")
	}
}
