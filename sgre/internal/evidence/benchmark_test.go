//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
)

func perfCorpusDir() string {
	return filepath.Join("..", "..", "testdata", "perf", "large_codebase")
}

// benchmarkDetectorStage builds the per-scan state the real pipeline hands to
// the detector stage: an indexed perf corpus, the semantic graph, the
// interprocedural alias graph, the repository declaration facts, and a
// RepoIndex snapshot in ctx. Setup is excluded from the measured time.
func benchmarkDetectorStage(b *testing.B) (db.Store, *parser.Parser, context.Context) {
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
	return store, p, ctx
}

// BenchmarkRunAllDetectors measures one full pass of the registered detector
// set with the shared statement-CFG cache the pipeline creates per scan. A
// fresh cache per iteration keeps a later iteration from reusing the previous
// iteration's CFG builds.
func BenchmarkRunAllDetectors(b *testing.B) {
	store, p, ctx := benchmarkDetectorStage(b)
	logger := log.New(io.Discard, log.LevelWarn)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := store.ClearSecurityEvents(ctx); err != nil {
			b.Fatalf("clear security events: %v", err)
		}
		cache := graph.NewCFGCache()
		cache.MaxEntries = 4000
		b.StartTimer()
		errs := RunAllDetectorsWithCache(ctx, store, p, logger, cache)
		b.StopTimer()
		cache.Reset()
		if len(errs) > 0 {
			b.Fatalf("detectors failed: %v", errs)
		}
	}
}

// BenchmarkReadCorpus measures one os.ReadFile pass over the corpus: the unit
// of I/O M-12 asked to quantify against BenchmarkRunAllDetectors. A detector
// stage issues one such pass per file-visiting detector pass, so the measured
// read cost times the pass count is the I/O share of the stage.
func BenchmarkReadCorpus(b *testing.B) {
	entries, err := os.ReadDir(perfCorpusDir())
	if err != nil {
		b.Fatalf("read perf corpus: %v", err)
	}
	var paths []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".c" {
			paths = append(paths, filepath.Join(perfCorpusDir(), entry.Name()))
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var total int
		for _, path := range paths {
			src, err := os.ReadFile(path)
			if err != nil {
				b.Fatalf("read %s: %v", path, err)
			}
			total += len(src)
		}
		if total == 0 {
			b.Fatal("read no bytes from the perf corpus")
		}
	}
}
