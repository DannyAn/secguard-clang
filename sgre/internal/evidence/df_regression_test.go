package evidence

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// TestDF_LoopParam_NoEvents pins the "field-free function is not a direct
// deallocator" fix for the loop case: health_free_content frees a FIELD of its
// first argument (via a local alias), not its second argument, so passing the
// loop counter i twice must not read as "double-free on 'i'".
func TestDF_LoopParam_NoEvents(t *testing.T) {
	store := runUAFDetectors(t, "tc_df_loop_param.c")
	assertNoEventOfType(t, store, "DOUBLE_FREE", "tc_df_loop_param")
	assertNoEventOfType(t, store, "USE_AFTER_FREE", "tc_df_loop_param")
}

// TestDF_IndirectDisjoint_NoCandidates runs the full double-free pipeline for an
// INDIRECT free (traverse_free_id_result frees its `int **` param) called twice
// on mutually-exclusive error paths. The detector may emit a raw DOUBLE_FREE,
// but the flow filter must dismiss it (the first free's branch returns).
func TestDF_IndirectDisjoint_NoCandidates(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc_df_disjoint_indirect.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	NewDoubleFreeDetector(store, p, logger).Detect(ctx)

	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "double-free")
	if err != nil {
		t.Fatalf("plan double-free: %v", err)
	}
	if res.CandidateCount() != 0 {
		t.Errorf("double-free: expected 0 candidates (mutually-exclusive indirect frees), got %d", res.CandidateCount())
		for _, c := range res.Candidates {
			t.Logf("  var=%q line=%d", c.Target.Variable, c.Target.Line)
		}
	}
}

// TestExtractParams_NestedPointerDeclarator pins the `int **result` param fix:
// the parameter name must be recovered through nested pointer_declarators, or
// every indirect-free summary for a double-pointer-param function is empty and
// its frees are silently missed.
func TestExtractParams_NestedPointerDeclarator(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc_df_disjoint_indirect.c")); err != nil {
		t.Fatalf("index: %v", err)
	}

	funcs, _ := store.ListFunctions(ctx)
	files, _ := store.ListFiles(ctx)
	for _, fn := range funcs {
		if fn.Name != "traverse_free_id_result" {
			continue
		}
		var file *db.File
		for _, f := range files {
			if f.ID == fn.FileID {
				file = f
			}
		}
		src, err := os.ReadFile(file.Path)
		if err != nil {
			t.Fatal(err)
		}
		tree, err := p.Parse(src, file.Path)
		if err != nil {
			t.Fatal(err)
		}
		params := extractFunctionParamsFrom(tree.RootNode().FindAll("function_definition"), fn.StartLine)
		if len(params) != 1 || params[0] != "result" {
			t.Errorf("traverse_free_id_result params = %v, want [result]", params)
		}
		return
	}
	t.Fatal("traverse_free_id_result not indexed")
}
