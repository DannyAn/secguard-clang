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

// TestDefiniteNull_MustAnalysis pins the must-null tier: `p = NULL` (an explicit
// null assignment) reaching a dereference is a CERTAIN null-deref, distinct from
// `p = malloc()` which is only a possible null. The former carries
// has_definite_null=true and must survive the pipeline.
func TestDefiniteNull_MustAnalysis(t *testing.T) {
	src := `#include <stdlib.h>

int certain_null_deref(void) {
    int *p = NULL;
    return *p;
}

int possible_null_deref(void) {
    int *q = malloc(sizeof(int));
    return *q;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "dn.c")
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

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	byFunc := map[string]bool{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = true
		if c.Target.Function == "certain_null_deref" {
			if !c.HasDefiniteNull {
				t.Errorf("certain_null_deref must carry has_definite_null=true")
			}
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("certain_null_deref (definite null) must be confirmed, got %q", c.SuspicionLevel)
			}
		}
		if c.Target.Function == "possible_null_deref" {
			if c.HasDefiniteNull {
				t.Errorf("possible_null_deref must NOT carry has_definite_null (it is only possibly-null)")
			}
			if c.SuspicionLevel != "suspected" {
				t.Errorf("possible_null_deref (possible null) must be suspected, got %q", c.SuspicionLevel)
			}
		}
	}
	if !byFunc["certain_null_deref"] {
		t.Errorf("certain_null_deref should be a finding, got %v", byFunc)
	}
}

// TestDefiniteNull_ForUpdateCopyKillsDefiniteNull pins the must-null tier on a
// for-loop update clause: `pre = NULL; for (...; pre = cur, ...) { ... }` must
// NOT treat pre as a definite null at a later dereference, because the update
// copy (`pre = cur`) overwrites the null. Before the fix the must analysis did
// not read comma_expression assignments, so `pre = NULL` stayed "definite null"
// on every path and the linked-list insert was auto-confirmed as CWE-476.
func TestDefiniteNull_ForUpdateCopyKillsDefiniteNull(t *testing.T) {
	src := `#include <stdlib.h>

struct node { int index; struct node *next; };
struct node *head;
int target_index;
int enable;

void linked_list_insert(void) {
    struct node *cur = head;
    struct node *pre = NULL;
    for (; cur != NULL; pre = cur, cur = cur->next) {
        if (cur->index == target_index) break;
    }
    if (enable) {
        if (cur != NULL) return;
        struct node *new_node = malloc(sizeof(struct node));
        if (new_node == NULL) return;
        new_node->index = target_index;
        new_node->next = NULL;
        if (head == NULL) {
            head = new_node;
        } else {
            pre->next = new_node;
        }
    }
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "ll.c")
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

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	sawPre := false
	for _, c := range result.Candidates {
		if c.Target.Variable != "pre" {
			continue
		}
		sawPre = true
		if c.HasDefiniteNull {
			t.Errorf("pre (assigned non-null in for update) must NOT carry has_definite_null")
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("pre must be suspected (possible null), got %q", c.SuspicionLevel)
		}
	}
	if !sawPre {
		t.Errorf("expected a pre dereference candidate, got none")
	}
}

// TestDefiniteNull_OutputParamKillsNull pins the output-parameter rule: `&p`
// passed to a call may write p through the pointer, so `p = NULL; init(&p); *p`
// must NOT be a definite null-deref, while a plain `p = NULL; *p` still is.
func TestDefiniteNull_OutputParamKillsNull(t *testing.T) {
	src := `#include <stdlib.h>

static int get(int **dst) {
    *dst = malloc(4);
    if (*dst == NULL) return -1;
    return 0;
}

void output_param_init(void) {
    int *p = NULL;
    if (get(&p) != 0) return;
    *p = 1;
}

int real_null(void) {
    int *p = NULL;
    return *p;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "op.c")
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

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	for _, c := range result.Candidates {
		if c.Target.Function == "output_param_init" && c.Target.Variable == "p" {
			if c.HasDefiniteNull {
				t.Errorf("output_param_init's p (written via &p) must NOT carry has_definite_null")
			}
		}
		if c.Target.Function == "real_null" {
			if !c.HasDefiniteNull {
				t.Errorf("real_null's p (plain p=NULL then *p) must carry has_definite_null")
			}
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("real_null must be confirmed, got %q", c.SuspicionLevel)
			}
		}
	}
}
