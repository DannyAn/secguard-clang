//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestDangerousFunction_BannedCalls pins CWE-676: calls to the built-in banned
// list are flagged, while memcpy (not banned) is not. Second run-through of the
// ADDING_A_VULN_TYPE.md standard.
func TestDangerousFunction_BannedCalls(t *testing.T) {
	store, p := setupDetector(t, "tc109_dangerous_function.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list DANGEROUS_FUNCTION: %v", err)
	}
	flagged := map[string]bool{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			flagged[props.Variable] = true
		}
	}

	for _, banned := range []string{"gets", "mktemp", "gethostbyname", "bcopy"} {
		if !flagged[banned] {
			t.Errorf("%s should be flagged as dangerous/obsolete, got %v", banned, flagged)
		}
	}
	if flagged["memcpy"] {
		t.Errorf("memcpy must NOT be flagged (not in the banned list), got %v", flagged)
	}
}

// TestDangerousFunction_ConfigExtension pins the enterprise-policy extension: a
// name listed in secguard.toml [banned_functions] is banned on top of the
// built-in list, so a project-specific deprecated wrapper is also flagged.
func TestDangerousFunction_ConfigExtension(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(tomlPath, []byte("[banned_functions]\nnames = [\"my_legacy_alloc\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(tomlPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

	src := `void *my_legacy_alloc(size_t n) { return 0; }

int use_legacy(void) {
    void *p = my_legacy_alloc(16);
    return p == 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "legacy.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list DANGEROUS_FUNCTION: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props.Variable == "my_legacy_alloc" {
			found = true
		}
	}
	if !found {
		t.Errorf("config-banned my_legacy_alloc should be flagged, got %d events", len(events))
	}
}
