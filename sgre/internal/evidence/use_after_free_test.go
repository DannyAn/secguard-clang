package evidence

import (
	"context"
	"encoding/json"
	"io"
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
