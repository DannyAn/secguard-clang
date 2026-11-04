//go:build !nosqlite

package db

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenWithOptionsAppliesSQLiteBudgets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "opts.db")
	d, err := OpenWithOptions(ctx, path, OpenOptions{CacheSizeKB: 4096, MmapSizeBytes: 8 << 20})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer d.Close()

	var cacheSize int
	if err := d.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&cacheSize); err != nil {
		t.Fatalf("PRAGMA cache_size: %v", err)
	}
	if cacheSize != -4096 {
		t.Fatalf("cache_size = %d, want -4096", cacheSize)
	}

	var mmapSize int64
	if err := d.QueryRowContext(ctx, "PRAGMA mmap_size").Scan(&mmapSize); err != nil {
		t.Fatalf("PRAGMA mmap_size: %v", err)
	}
	if mmapSize != 8<<20 {
		t.Fatalf("mmap_size = %d, want %d", mmapSize, int64(8<<20))
	}
}
