//go:build !nosqlite

package graph

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func perfCorpusDir() string {
	return filepath.Join("..", "..", "testdata", "perf", "large_codebase")
}

// benchmarkIndexedCorpus indexes the committed perf corpus once per benchmark
// (setup is excluded from the measured time) and returns the store plus a
// parser whose parse cache is still cold.
func benchmarkIndexedCorpus(b *testing.B) (db.Store, *parser.Parser) {
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
	return store, p
}

// BenchmarkBuildCallGraph measures a from-empty CALL edge build. ClearGraph
// runs between iterations because graph builders append edges rather than
// replacing them (the pipeline clears the graph once before a rebuild).
func BenchmarkBuildCallGraph(b *testing.B) {
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	store, p := benchmarkIndexedCorpus(b)
	builder := NewCallGraphBuilder(store, p, logger)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := store.ClearGraph(ctx); err != nil {
			b.Fatalf("clear graph: %v", err)
		}
		b.StartTimer()
		if _, err := builder.Build(ctx); err != nil {
			b.Fatalf("build call graph: %v", err)
		}
	}
}

// BenchmarkBuildDataFlow measures a from-empty DATA_FLOW edge build.
func BenchmarkBuildDataFlow(b *testing.B) {
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	store, p := benchmarkIndexedCorpus(b)
	builder := NewDataFlowBuilder(store, p, logger)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := store.ClearGraph(ctx); err != nil {
			b.Fatalf("clear graph: %v", err)
		}
		b.StartTimer()
		if _, err := builder.Build(ctx); err != nil {
			b.Fatalf("build data flow: %v", err)
		}
	}
}

func benchmarkParsedCorpus(b *testing.B) []parser.Node {
	b.Helper()
	entries, err := os.ReadDir(perfCorpusDir())
	if err != nil {
		b.Fatalf("read perf corpus: %v", err)
	}
	p := parser.NewParser()
	p.SetMaxCachedTrees(4000)
	var roots []parser.Node
	var trees []*parser.Tree
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".c" {
			continue
		}
		path := filepath.Join(perfCorpusDir(), entry.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			b.Fatalf("read %s: %v", path, err)
		}
		tree, err := p.ParseCached(src, path)
		if err != nil {
			b.Fatalf("parse %s: %v", path, err)
		}
		roots = append(roots, tree.RootNode())
		trees = append(trees, tree)
	}
	b.Cleanup(func() {
		for _, tree := range trees {
			tree.Release()
		}
		p.CloseAll()
	})
	if len(roots) == 0 {
		b.Fatalf("perf corpus %s has no .c files", perfCorpusDir())
	}
	return roots
}

// BenchmarkBuildStmtCFG measures statement-level CFG construction for every
// function in the corpus. The parse trees are primed and borrowed before the
// timer starts, so this isolates CFG building from parse and file I/O.
func BenchmarkBuildStmtCFG(b *testing.B) {
	roots := benchmarkParsedCorpus(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, root := range roots {
			for _, def := range root.FindAll("function_definition") {
				body := def.FindFirst("compound_statement")
				if body == nil {
					continue
				}
				cfg := BuildStmtCFG(*body, def.EndLine())
				if cfg == nil || len(cfg.Nodes) == 0 {
					b.Fatalf("empty CFG for function at line %d", def.StartLine())
				}
			}
		}
	}
}
