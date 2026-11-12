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

// TestUAF_Issue263_ContainerPayloadNotUAF pins the issue #263 4.3 shapes:
// freeing a container's PAYLOAD (free(b->data), directly, through a field
// alias, or through a wrapper callee) must not dangle the container's own
// fields — only a whole-container free does. The detector's field matching
// (freeSite.field vs use.field) is the guard; these cases keep it from
// regressing into the auto-confirmed false positives the issue reported.
func TestUAF_Issue263_ContainerPayloadNotUAF(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	src := `#include <stdlib.h>

struct buf263 {
    unsigned char *data;
    int in_use;
    size_t len;
};

/* issue skeleton: free the payload, then touch the container */
void buf_clear(struct buf263 *b)
{
    free(b->data);
    b->data = NULL;
    b->in_use = 0;
}

/* alias form: p = b->data; free(p) — a field alias, not the container */
void buf_clear_alias(struct buf263 *b)
{
    unsigned char *p = b->data;
    free(p);
    b->data = NULL;
    b->in_use = 0;
}

/* wrapper form: the callee frees the payload argument */
static void payload_release(unsigned char *p)
{
    free(p);
}

void buf_clear_wrapper(struct buf263 *b)
{
    payload_release(b->data);
    b->data = NULL;
    b->in_use = 0;
}

/* control: freeing the CONTAINER dangles its fields — a real UAF */
int uaf_control(void)
{
    struct buf263 *b = malloc(sizeof *b);
    if (b == 0) return -1;
    b->data = malloc(8);
    b->in_use = 1;
    free(b);
    return b->in_use;
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "uaf_container.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	result, err := NewPlanner(store, p, logger).Plan(ctx, "use-after-free")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	byFunc := map[string]string{}
	for _, c := range result.Candidates {
		byFunc[c.Target.Function] = c.SuspicionLevel
	}
	for _, fn := range []string{"buf_clear", "buf_clear_alias", "buf_clear_wrapper"} {
		if tier, ok := byFunc[fn]; ok {
			t.Errorf("%s: freeing the payload must not dangle the container, got %s candidate", fn, tier)
		}
	}
	if byFunc["uaf_control"] != "confirmed" {
		t.Errorf("uaf_control = %q, want confirmed (freeing the container is a real UAF)", byFunc["uaf_control"])
	}
}
