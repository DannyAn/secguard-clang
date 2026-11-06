//go:build !nosqlite

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/report"
)

func TestWriteSuggestedConfig_WritesOnceAndNeverOverwrites(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)

	fileID, err := store.InsertFile(ctx, &db.File{Path: "/proj/app.c", Language: "c", Checksum: "x", LOC: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "myapp_malloc", Signature: "myapp_malloc(size_t n)", ReturnType: "void*"}); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	status := writeSuggestedConfig(ctx, store, root)
	if !strings.HasPrefix(status, "written: ") {
		t.Fatalf("first write status = %q, want written", status)
	}
	path := report.SuggestedConfigPath(root)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("suggested file missing at %s: %v", path, err)
	}
	if !strings.Contains(string(data), "[allocators]") || !strings.Contains(string(data), "myapp_malloc") {
		t.Errorf("suggested file lacks the discovered allocator:\n%s", data)
	}

	// A second index must not overwrite an existing (possibly hand-edited) file.
	status = writeSuggestedConfig(ctx, store, root)
	if !strings.HasPrefix(status, "skipped (already exists)") {
		t.Fatalf("second write status = %q, want skipped", status)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(data) {
		t.Errorf("existing suggestion was modified")
	}

	// Removing the .suggested suffix is the documented adoption path: the loader
	// probes the sibling secguard.toml when the canonical project config is absent.
	adopted := filepath.Join(filepath.Dir(path), "secguard.toml")
	if err := os.Rename(path, adopted); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(adopted); err != nil {
		t.Errorf("renamed suggestion missing: %v", err)
	}
}
