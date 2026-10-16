//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// E-03 regression: a contract@unknown unchecked-return candidate must carry the
// callee's definition location. The callee is typically a `*_new` factory
// defined in ANOTHER file (pool.c, called from server.c), so the classifier's
// proof burden ("prove the callee returns a failure sentinel or dismiss")
// cannot be met from a ±8 window. An external callee (declared with a pointer
// return type, never defined in the scan) must stay unlocated — pointing at a
// declaration would send the classifier to read a prototype.
func TestUncheckedReturn_CalleeDefinitionLocation(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	poolSrc := `#include <stdlib.h>
#include <string.h>

char *str_dup_new(const char *s) {
    char *d = malloc(strlen(s) + 1);
    if (d == NULL) return NULL;
    strcpy(d, s);
    return d;
}
`
	serverSrc := `char *str_dup_new(const char *s);
char *ext_buf_dup(const char *s);

void handle(const char *s) {
    str_dup_new(s);
}

void handle_ext(const char *s) {
    ext_buf_dup(s);
}
`
	if err := os.WriteFile(filepath.Join(dir, "pool.c"), []byte(poolSrc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.c"), []byte(serverSrc), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join(dir, "pool.c")); err != nil {
		t.Fatalf("index pool.c: %v", err)
	}
	if _, err := idx.Index(ctx, filepath.Join(dir, "server.c")); err != nil {
		t.Fatalf("index server.c: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewUncheckedReturnDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "unchecked-return")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	var inScan, external *EvidenceItem
	for i := range result.Candidates {
		c := &result.Candidates[i]
		switch c.Target.Function {
		case "handle":
			inScan = c
		case "handle_ext":
			external = c
		}
	}
	if inScan == nil {
		names := make([]string, 0, len(result.Candidates))
		for _, c := range result.Candidates {
			names = append(names, c.Target.Function)
		}
		t.Fatalf("handle (unchecked str_dup_new) must be a candidate; got %v", names)
	}
	if !strings.HasSuffix(inScan.CalleeDefFile, "pool.c") || inScan.CalleeDefLine == 0 {
		t.Errorf("in-scan callee: CalleeDefFile/Line = %q/%d, want pool.c:<def line>", inScan.CalleeDefFile, inScan.CalleeDefLine)
	}
	if !strings.Contains(inScan.Hint, "callee@pool.c:") {
		t.Errorf("in-scan callee: Hint %q must carry callee@pool.c:<line>", inScan.Hint)
	}
	fragOK := false
	for _, f := range inScan.Evidence {
		if strings.Contains(f.Detail, "defined in the scan at") && strings.Contains(f.Detail, "pool.c") {
			fragOK = true
		}
	}
	if !fragOK {
		t.Errorf("in-scan callee: evidence must carry the definition location, got %+v", inScan.Evidence)
	}

	if external == nil {
		names := make([]string, 0, len(result.Candidates))
		for _, c := range result.Candidates {
			names = append(names, c.Target.Function)
		}
		t.Fatalf("handle_ext (unchecked ext_buf_dup) must be a candidate; got %v", names)
	}
	if external.CalleeDefFile != "" {
		t.Errorf("external callee: CalleeDefFile = %q, want empty (declaration is not a definition)", external.CalleeDefFile)
	}
	extOK := false
	for _, f := range external.Evidence {
		if strings.Contains(f.Detail, "no definition in the scan") {
			extOK = true
		}
	}
	if !extOK {
		t.Errorf("external callee: evidence must say no definition in scan, got %+v", external.Evidence)
	}
}
