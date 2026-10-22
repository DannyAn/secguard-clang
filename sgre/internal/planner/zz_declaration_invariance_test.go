//go:build !nosqlite

package planner

import (
	"io"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Declaration-fact invariance: moving a struct / array / macro / typedef into a
// header — the normal C layout, `axxx.h -> axxx.c`, `axxx.h + bxxx.h -> cxxx.c`
// — must NOT change what the declaration-fact detectors report.
//
// This is the class-level guard for a recurring failure: a detector cached
// `root.FindAll(...)` of the file it was analyzing, so a declaration living in a
// header silently vanished from its view. Same-file fixtures passed while
// production produced zero candidates (out-of-bounds `svr[actived_index]` was the
// case that slipped through ten rounds).
func TestDeclarationFactInvariance(t *testing.T) {
	cases := []struct {
		name   string
		types  []string
		inline map[string]string
		split  map[string]string
	}{
		{
			name:  "out-of-bounds: struct member array + field index",
			types: []string{"out-of-bounds"},
			inline: map[string]string{"oob.c": `#define CAP 4

struct decl_inv_s {
    unsigned int idx;
    int arr[CAP];
};

int decl_inv_read(struct decl_inv_s *s)
{
    return s->arr[s->idx];
}

int main(void) { return 0; }
`},
			split: map[string]string{
				"decl_inv.h": `#define CAP 4

struct decl_inv_s {
    unsigned int idx;
    int arr[CAP];
};
`,
				"oob.c": `#include "decl_inv.h"

int decl_inv_read(struct decl_inv_s *s)
{
    return s->arr[s->idx];
}

int main(void) { return 0; }
`,
			},
		},
		{
			name:  "buffer-overflow: file-scope destination array from a header",
			types: []string{"buffer-overflow"},
			inline: map[string]string{"buf.c": `char g_decl_inv_dst[16];

void decl_inv_copy(char *src)
{
    memcpy(g_decl_inv_dst, src, 64);
}

int main(void) { return 0; }
`},
			split: map[string]string{
				"decl_inv_buf.h": `extern char g_decl_inv_dst[16];
`,
				"buf.c": `#include "decl_inv_buf.h"

void decl_inv_copy(char *src)
{
    memcpy(g_decl_inv_dst, src, 64);
}

int main(void) { return 0; }
`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := declarationInvariancePlan(t, tc.inline, tc.types)
			got := declarationInvariancePlan(t, tc.split, tc.types)
			if len(want) == 0 {
				t.Fatalf("the inline fixture produced no candidate — the case is not exercising the detector")
			}
			if len(want) != len(got) {
				t.Fatalf("header-split changed the candidate set:\n inline=%v\n split =%v", want, got)
			}
			for i := range want {
				if want[i] != got[i] {
					t.Fatalf("header-split changed the candidate set:\n inline=%v\n split =%v", want, got)
				}
			}
		})
	}
}

// declarationInvariancePlan runs the declaration-fact detectors over a fixture
// set and returns a sorted, line-free signature per candidate: moving a
// declaration into a header legitimately shifts line numbers, but must not add,
// drop or re-target a candidate.
func declarationInvariancePlan(t *testing.T, files map[string]string, types []string) []string {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	var paths []string
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
		paths = append(paths, path)
	}
	idx := indexer.NewIndexer(store, logger)
	for _, path := range paths {
		if _, err := idx.Index(ctx, path); err != nil {
			t.Fatalf("index %s: %v", path, err)
		}
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewCallerNullDetector(store, p, logger).Detect(ctx)
	evidence.NewBufferOverflowDetector(store, p, logger).Detect(ctx)
	evidence.NewSignedCompareDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	var out []string
	for _, typ := range types {
		res, err := pl.Plan(ctx, typ)
		if err != nil {
			t.Fatalf("plan %s: %v", typ, err)
		}
		for _, c := range res.Candidates {
			out = append(out, typ+"|"+c.Target.Function+"|"+c.Target.Variable)
		}
	}
	sort.Strings(out)
	return out
}
