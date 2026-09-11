//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUninit_IterMacroConfigDeclared pins the secguard.toml iterator-macro
// declaration for the UNINIT pipeline: `SLL_SCAN(list, iter, type)` is defined
// in a third-party SDK header outside the scan tree, so the per-file macro
// write-summary can never see it. The user declares it in
// [iterator_macros.macros] with iterator arg index 1; the detector must treat
// that argument as a WRITE target (the for-init assigns it), so the iterator is
// not misreported as use-before-init — while a genuine uninit read is reported.
func TestUninit_IterMacroConfigDeclared(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(tomlPath, []byte("[iterator_macros.macros]\nSLL_SCAN = [1]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(tomlPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

	src := `typedef unsigned int UINT32;
typedef struct SLL { UINT32 uiCount; } SLL_S;

int sll_scan_use(SLL_S *sll)
{
    UINT32 idx;
    SLL_SCAN(sll, idx, UINT32) {
        if (sll->uiCount == idx) {
            return 1;
        }
    }
    return (int)idx;
}

int real_uninit_bug(void)
{
    UINT32 handle;
    return (int)handle;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "sll.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	result, err := NewPlanner(store, p, logger).Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	if c := candidateForFunc(t, result, "sll_scan_use"); c != nil {
		t.Errorf("sll_scan_use should NOT be flagged (SLL_SCAN writes idx via config iterator-macro), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if c := candidateForFunc(t, result, "real_uninit_bug"); c == nil {
		t.Errorf("real_uninit_bug must be flagged (handle never initialized), got: %s", candidateNames(result))
	}
}
