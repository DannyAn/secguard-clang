//go:build !nosqlite

package repofacts

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// buildFactsFromFiles indexes a synthetic tree and returns its declaration
// facts, so the pointer-member census is tested through the same Build path the
// detectors use (including the tagged/alias/conflict resolution).
func buildFactsFromFiles(t *testing.T, files map[string]string) *Facts {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, dir); err != nil {
		t.Fatalf("index: %v", err)
	}
	facts, err := Build(ctx, store, p, logger)
	if err != nil {
		t.Fatalf("build facts: %v", err)
	}
	return facts
}

// TestPointerFields_TagAliasAndNesting locks the pointer-member census the
// global-container shallow-free analysis consumes: a tagged struct and its
// typedef alias both resolve, non-pointer members and array-of-pointer members
// are excluded, and an inline nested struct's member is not attributed to the
// outer type.
func TestPointerFields_TagAliasAndNesting(t *testing.T) {
	facts := buildFactsFromFiles(t, map[string]string{
		"shape.c": `typedef struct node_s {
    int *ptr;
    int val;
    char buf[8];
    struct {
        int *inner;
    } nested;
    int *slots[4];
} node_t;
`,
	})

	for _, key := range []string{"node_s", "node_t"} {
		got, ok := facts.PointerFields(key)
		if !ok {
			t.Fatalf("PointerFields(%q): no facts", key)
		}
		if want := []string{"ptr"}; !reflect.DeepEqual(got, want) {
			t.Errorf("PointerFields(%q) = %v, want %v", key, got, want)
		}
	}
	if got, _ := facts.PointerFields("node_s"); contains(got, "nested") || contains(got, "inner") || contains(got, "slots") {
		t.Errorf("nested/array members leaked into the pointer census: %v", got)
	}
}

// TestPointerFields_AnonymousTypedef covers the ubiquitous
// `typedef struct {...} T;` shape, whose only census key is the alias.
func TestPointerFields_AnonymousTypedef(t *testing.T) {
	facts := buildFactsFromFiles(t, map[string]string{
		"anon.c": `typedef struct {
    char *name;
} anon_t;
`,
	})
	got, ok := facts.PointerFields("anon_t")
	if !ok {
		t.Fatalf("PointerFields(anon_t): no facts")
	}
	if want := []string{"name"}; !reflect.DeepEqual(got, want) {
		t.Errorf("PointerFields(anon_t) = %v, want %v", got, want)
	}
}

// TestPointerFields_ConflictDropped: two definitions of the same tag that
// disagree on a member's pointer-ness must drop that member (a guessed shape is
// worse than an unknown one), while the unambiguous member survives.
func TestPointerFields_ConflictDropped(t *testing.T) {
	facts := buildFactsFromFiles(t, map[string]string{
		"a.c": `struct dup { int *f; int *shared; };
`,
		"b.c": `struct dup { int f; int *shared; };
`,
	})
	got, ok := facts.PointerFields("dup")
	if !ok {
		t.Fatalf("PointerFields(dup): expected the unambiguous member to survive")
	}
	if contains(got, "f") {
		t.Errorf("conflicting member f must be dropped, got %v", got)
	}
	if !contains(got, "shared") {
		t.Errorf("unambiguous pointer member shared must survive, got %v", got)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
