//go:build !nosqlite

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

// runDoubleFreeDetectorWithAlias indexes a fixture, builds the per-scan
// AliasGraph (attached to ctx), and runs the double-free detector.
func runDoubleFreeDetectorWithAlias(t *testing.T, src string) []*db.SecurityEvent {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	defer p.CloseAll()

	dir := t.TempDir()
	path := filepath.Join(dir, "df.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)

	ag, err := graph.BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		t.Fatalf("BuildInterproceduralAlias: %v", err)
	}
	ctx = graph.WithAliasGraph(ctx, ag)

	NewDoubleFreeDetector(store, p, logger).Detect(ctx)
	events, err := store.ListEventsByType(ctx, "DOUBLE_FREE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	return events
}

func crossFunctionEvents(events []*db.SecurityEvent) []string {
	var out []string
	for _, e := range events {
		var props struct {
			CrossFunction bool   `json:"cross_function"`
			Variable      string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		if props.CrossFunction {
			out = append(out, props.Variable)
		}
	}
	return out
}

// TestDoubleFree_CrossFunctionReturnAlias pins the sound cross-function
// double-free: a callee that UNCONDITIONALLY frees its return value
// (`free(p); return p;`) and a caller that frees the result are one defect —
// the dangling-return alias collapses the two frees into a cross_function
// DOUBLE_FREE event.
func TestDoubleFree_CrossFunctionReturnAlias(t *testing.T) {
	events := runDoubleFreeDetectorWithAlias(t, `
void *malloc(long);
void free(void *);
void *make_ptr(void) {
    void *p = malloc(16);
    free(p);
    return p;
}
void caller(void) {
    void *q = make_ptr();
    free(q);
}
`)
	if got := crossFunctionEvents(events); len(got) == 0 {
		t.Fatal("expected a cross_function DOUBLE_FREE event for the dangling-return double-free, got none")
	}
}

// TestDoubleFree_CrossFunctionConditionalFreeNotCollapsed pins the dangling-
// return gate: a callee that frees its return value only on an ERROR path
// (`if (fail) { free(entry); return NULL; } return entry;`) returns a LIVE
// object on success, so the caller's free is NOT a double-free and must not
// collapse (the allocator.c alloc_entry shape).
func TestDoubleFree_CrossFunctionConditionalFreeNotCollapsed(t *testing.T) {
	events := runDoubleFreeDetectorWithAlias(t, `
void *malloc(long);
void free(void *);
void *alloc_entry(int fail) {
    void *entry = malloc(16);
    if (!entry) return NULL;
    if (fail) {
        free(entry);
        return NULL;
    }
    return entry;
}
void process(void) {
    void *q = alloc_entry(0);
    free(q);
}
`)
	if got := crossFunctionEvents(events); len(got) != 0 {
		t.Errorf("conditional free must not produce a cross_function event, got %v", got)
	}
}

// TestDoubleFree_CrossFunctionParamAliasNotCollapsed pins the kind gate: a
// parameter-alias shape (`release(p)` + `free(p)` inside release) is never
// collapsed with a caller's free — the parameter may be a different object on
// every call, and the aggregation only follows dangling-return edges.
func TestDoubleFree_CrossFunctionParamAliasNotCollapsed(t *testing.T) {
	events := runDoubleFreeDetectorWithAlias(t, `
void *malloc(long);
void free(void *);
void release(void *entry) {
    free(entry);
}
void alloc(void) {
    void *entry = malloc(16);
    release(entry);
}
`)
	if got := crossFunctionEvents(events); len(got) != 0 {
		t.Errorf("parameter-alias frees must not produce a cross_function event, got %v", got)
	}
}
