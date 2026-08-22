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

// TestDoubleFree_DirectFieldFree pins field-granular double-free detection:
// free(p->msg) twice is a double-free of p->msg, while freeing two DIFFERENT
// fields is not.
func TestDoubleFree_DirectFieldFree(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "df_field.c")
	src := `#include <stdlib.h>

struct Node { struct Node *msg; struct Node *mode; };

int tp_same_field(struct Node *p) {
    free(p->msg);
    free(p->msg);
    return 0;
}

int fp_different_field(struct Node *q) {
    free(q->msg);
    free(q->mode);
    return 0;
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
	NewDoubleFreeDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "DOUBLE_FREE")
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

	if !flagged["p->msg"] {
		t.Errorf("expected double-free of p->msg (same field twice) to be flagged, got %v", flagged)
	}
	if flagged["q->msg"] || flagged["q->mode"] {
		t.Errorf("expected freeing two different fields NOT to be a double-free, got %v", flagged)
	}
}
