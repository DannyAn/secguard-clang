package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUseAfterFree_FieldFreeScope locks in the field-free scoping fix: a callee
// that frees `s->msg` dangles only that field, so a later read of `s->mode`
// must NOT be flagged, while a whole-variable `free(p)` followed by `p->mode`
// still must be.
func TestUseAfterFree_FieldFreeScope(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc45_field_free_scope.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "USE_AFTER_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	flagged := map[string][]int{} // variable -> use lines
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			UseLine  int    `json:"use_line"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable != "" && props.UseLine > 0 {
			flagged[props.Variable] = append(flagged[props.Variable], props.UseLine)
		}
	}

	// use_after_whole_free: free(p) then p->mode must stay flagged.
	foundWhole := false
	for _, fn := range []string{"p"} {
		if len(flagged[fn]) > 0 {
			foundWhole = true
		}
	}
	if !foundWhole {
		t.Errorf("expected whole-variable free(p) then p->mode to be flagged, got flagged vars %v", flagged)
	}

	// use_mode_after_msg_free: clear_msg(s) frees s->msg, then s->mode is read;
	// this must NOT surface as a use-after-free of s.
	if len(flagged["s"]) > 0 {
		t.Errorf("expected field free of s->msg NOT to flag s->mode uses, got flagged lines %v", flagged["s"])
	}
}

// TestUseAfterFree_ConditionalFieldFree locks in the path-sensitive free
// summary: a callee that frees a field only on an error-return path does NOT
// dangle the field on the fall-through path, so a caller that checks the error
// before using the field is not a use-after-free — while an unconditional
// whole-variable free still is.
func TestUseAfterFree_ConditionalFieldFree(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc55_conditional_field_free.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "USE_AFTER_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	flagged := map[string]bool{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Variable] = true
	}

	// caller_checks_error uses s->out only after lookup() returned success, and
	// lookup's free(s->out) is on the error path — so `s` must NOT be flagged.
	if flagged["s"] {
		t.Errorf("expected conditional error-path free of s->out NOT to flag s, got %v", flagged)
	}
	// caller_whole_free does free(p) unconditionally then uses p->out — `p`
	// must still be flagged.
	if !flagged["p"] {
		t.Errorf("expected whole-variable free(p) then p->out to be flagged, got %v", flagged)
	}
}

// TestUseAfterFree_DirectFieldFree pins direct field-free detection: `free(p->msg)`
// dangles a later use of p->msg, but not a later use of a DIFFERENT field p->mode.
func TestUseAfterFree_DirectFieldFree(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "field_free.c")
	src := `#include <stdlib.h>

struct Node { int value; struct Node *msg; struct Node *mode; };

int tp_same_field(struct Node *p) {
    free(p->msg);
    return p->msg->value;
}

int fp_different_field(struct Node *q) {
    free(q->msg);
    return q->mode->value;
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "USE_AFTER_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	flagged := map[string]bool{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Variable] = true
	}

	if !flagged["p"] {
		t.Errorf("expected free(p->msg) then use(p->msg) to be flagged, got %v", flagged)
	}
	if flagged["q"] {
		t.Errorf("expected free(q->msg) then use(q->mode) NOT to be flagged, got %v", flagged)
	}
}

// TestUseAfterFree_SubscriptFree pins constant-index subscript free detection:
// free(arr[0]) dangles a later use of arr[0], but not a use of arr[1].
func TestUseAfterFree_SubscriptFree(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "sub_free.c")
	src := `#include <stdlib.h>

int tp_same_slot(void) {
    char *arr[2];
    arr[0] = (char *)malloc(16);
    free(arr[0]);
    return *arr[0];
}

int fp_different_slot(void) {
    char *arr[2];
    arr[0] = (char *)malloc(16);
    arr[1] = (char *)malloc(16);
    free(arr[0]);
    return *arr[1];
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "USE_AFTER_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	fields := map[string]bool{}
	for _, e := range events {
		var props struct {
			FreedField string `json:"freed_field"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.FreedField != "" {
			fields[props.FreedField] = true
		}
	}

	if !fields["arr[0]"] {
		t.Errorf("expected free(arr[0]) then use(arr[0]) to be flagged, got freed fields %v", fields)
	}
	if fields["arr[1]"] {
		t.Errorf("expected free(arr[0]) then use(arr[1]) NOT to be flagged, got %v", fields)
	}
}
