//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
)

func perfCorpusDir() string {
	return filepath.Join("..", "..", "testdata", "perf", "large_codebase")
}

// benchmarkPlannedStore prepares the state a plan stage starts from: the perf
// corpus indexed, the semantic graph built, and one detector pass already
// emitted the security events that seed candidates. Setup is excluded from the
// measured time.
func benchmarkPlannedStore(b *testing.B) (db.Store, *parser.Parser, context.Context) {
	b.Helper()
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	sqlDB, err := db.OpenInMemory(ctx)
	if err != nil {
		b.Fatalf("open in-memory store: %v", err)
	}
	store := db.NewStore(sqlDB)
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, perfCorpusDir()); err != nil {
		b.Fatalf("index perf corpus: %v", err)
	}
	idx.Close()

	p := parser.NewParser()
	p.SetMaxCachedTrees(4000)
	b.Cleanup(func() {
		p.CloseAll()
		if err := store.Close(); err != nil {
			b.Errorf("close store: %v", err)
		}
	})

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		b.Fatalf("list functions: %v", err)
	}
	files, err := store.ListFiles(ctx)
	if err != nil {
		b.Fatalf("list files: %v", err)
	}
	ctx = graph.WithRepoIndex(ctx, graph.NewRepoIndex(funcs, files))

	if err := graph.NewFuncPtrWriteBuilder(store, p, logger).Build(ctx); err != nil {
		b.Fatalf("build func ptr writes: %v", err)
	}
	builders := []struct {
		name string
		run  func() error
	}{
		{"call graph", func() error {
			_, err := graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"data flow", func() error {
			_, err := graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"alias", func() error {
			_, err := graph.NewAliasBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"ownership", func() error {
			_, err := graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"interproc", func() error {
			_, err := graph.NewInterprocBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"lock order", func() error {
			_, err := graph.NewLockOrderBuilder(store, p, logger).Build(ctx)
			return err
		}},
		{"shared access", func() error {
			_, err := graph.NewSharedAccessBuilder(store, p, logger).Build(ctx)
			return err
		}},
	}
	for _, builder := range builders {
		if err := builder.run(); err != nil {
			b.Fatalf("build %s: %v", builder.name, err)
		}
	}

	aliasGraph, err := graph.BuildInterproceduralAlias(ctx, store, p)
	if err != nil {
		b.Fatalf("build alias graph: %v", err)
	}
	ctx = graph.WithAliasGraph(ctx, aliasGraph)

	facts, err := repofacts.Build(ctx, store, p, logger)
	if err != nil {
		b.Fatalf("build repo facts: %v", err)
	}
	ctx = repofacts.WithFacts(ctx, facts)

	if err := store.ClearSecurityEvents(ctx); err != nil {
		b.Fatalf("clear security events: %v", err)
	}
	if errs := evidence.RunAllDetectorsWithCache(ctx, store, p, logger, graph.NewCFGCache()); len(errs) > 0 {
		b.Fatalf("detectors failed: %v", errs)
	}
	return store, p, ctx
}

// BenchmarkPlanAllTypes measures one sequential Plan() run for every active
// vulnerability type. It uses a fresh Planner (and CFG cache) per iteration so
// a later iteration never reuses the previous one's per-scan caches; the
// parse-tree cache stays warm, which matches a real scan whose plan stage
// follows the detector stage. The pipeline runs Plan concurrently; this
// sequential sum is a stable per-type cost baseline, not the stage's wall
// clock.
func BenchmarkPlanAllTypes(b *testing.B) {
	store, p, ctx := benchmarkPlannedStore(b)
	logger := log.New(io.Discard, log.LevelWarn)
	names := ActiveVulnTypes(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pl := NewPlanner(store, p, logger)
		b.StartTimer()
		if err := pl.PrewarmTaintSummary(ctx); err != nil {
			b.Fatalf("prewarm taint summary: %v", err)
		}
		for _, name := range names {
			if _, err := pl.Plan(ctx, name); err != nil {
				b.Fatalf("plan %s: %v", name, err)
			}
		}
	}
}
