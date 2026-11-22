//go:build !nosqlite

package indexer

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
)

// BenchmarkIndexCorpus measures the index stage over the committed perf corpus
// (100 files / 5,000 functions). Each iteration uses a fresh in-memory store so
// the checksum-based incremental skip cannot make a later iteration look
// cheaper than a first scan.
func BenchmarkIndexCorpus(b *testing.B) {
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	corpus := filepath.Join("..", "..", "testdata", "perf", "large_codebase")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		sqlDB, err := db.OpenInMemory(ctx)
		if err != nil {
			b.Fatalf("open in-memory store: %v", err)
		}
		store := db.NewStore(sqlDB)
		idx := NewIndexer(store, logger)
		b.StartTimer()
		if _, err := idx.Index(ctx, corpus); err != nil {
			b.Fatalf("index corpus: %v", err)
		}
		b.StopTimer()
		idx.Close()
		if err := store.Close(); err != nil {
			b.Fatalf("close store: %v", err)
		}
	}
}
