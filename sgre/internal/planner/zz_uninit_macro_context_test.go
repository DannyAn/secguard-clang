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

// TestUninit_MacroContextNotConfirmed pins the macro-context downgrade: a
// certainly-uninitialized read whose statement involves an ALL_CAPS function-like
// macro (the nlog HTONBUF/NTOHBUF accessor pattern) must stay suspected for the
// AI — never auto-confirmed, because the flow model cannot see the macro's write.
func TestUninit_MacroContextNotConfirmed(t *testing.T) {
	src := `#define MYMACRO(x) (x)
int f(void) {
    int a;
    return a + 1 + MYMACRO(0);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "macro.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewUninitVariableDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	found := false
	for _, c := range result.Candidates {
		if c.Target.Function == "f" && c.Target.Variable == "a" {
			found = true
			if c.SuspicionLevel == "confirmed" {
				t.Errorf("macro-context uninit of a must not be auto-confirmed, got %q (hint %q)", c.SuspicionLevel, c.Hint)
			}
			if !c.MacroContext {
				t.Errorf("expected MacroContext=true for the ALL_CAPS macro on the read line, got false")
			}
		}
	}
	if !found {
		t.Fatal("expected a candidate for the uninitialized read of a, got none")
	}
}
