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

// TestHardcodedSecret_PathTemplateIsNotSecret pins the A.7b fix: an XPath /
// data-model path template (`/example-model:cfg/...`) is high-entropy by Shannon
// measure but is a query template, not a credential, so it must not be emitted
// (let alone auto-confirmed). A genuine high-entropy secret still is.
func TestHardcodedSecret_PathTemplateIsNotSecret(t *testing.T) {
	src := `#include <stdio.h>
#include <stdint.h>

#define XPATH_LEN 256

int get_loc_cfg(const char *zoneName, uint32_t type, const char *locName)
{
    char *path = "/example-model:cfg/cfg-zone[zone-name=\"%s\"]/location[type=\"%u\"][loc-name=\"%s\"]";
    char datapath[XPATH_LEN] = {0};
    int ret = snprintf(datapath, XPATH_LEN, path, zoneName, type, locName);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

char *g_api_key = "xJ9kL2mN8pQ4rS6tU8vW0yA3bC5dE7fG";
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "a.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewHardcodedSecretDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	result, err := NewPlanner(store, p, logger).Plan(ctx, "hardcoded-secret")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	sawPath, sawKey := false, false
	for _, c := range result.Candidates {
		switch c.Target.Variable {
		case "path":
			sawPath = true
			t.Errorf("path (XPath template) must not be a hardcoded-secret candidate")
		case "g_api_key":
			sawKey = true
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("g_api_key (value-proven secret) must stay confirmed, got %q", c.SuspicionLevel)
			}
		}
	}
	if !sawKey {
		t.Errorf("g_api_key must remain a hardcoded-secret candidate (control)")
	}
	if sawPath {
		t.Errorf("path must be excluded")
	}
}
