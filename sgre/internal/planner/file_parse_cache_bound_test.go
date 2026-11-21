package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestFileParseCacheMaxEntriesFollowsParserBound locks in that the file parse
// cache pins at most the parser's configured AST-cache bound (issue #301): a
// hardcoded 256 evicted files whose trees were still resident in the parser
// cache, so the UAF/double-free/uninit flow filters re-read and re-walked files
// on any codebase larger than 256 without saving any tree memory.
func TestFileParseCacheMaxEntriesFollowsParserBound(t *testing.T) {
	p := parser.NewParser()
	p.SetMaxCachedTrees(7)
	cache := newFileParseCache(p)
	if cache.maxEntries != 7 {
		t.Fatalf("maxEntries = %d, want 7 (parser bound)", cache.maxEntries)
	}
	cache.Close()

	// A parser without SetMaxCachedTrees is unbounded (0), and the file cache
	// must stay unbounded too instead of imposing its own limit.
	p2 := parser.NewParser()
	cache2 := newFileParseCache(p2)
	if cache2.maxEntries != 0 {
		t.Fatalf("unbounded parser: maxEntries = %d, want 0", cache2.maxEntries)
	}
	cache2.Close()
}

// TestFileParseCacheEvictionReprimes pins the eviction re-prime behavior: after
// the LRU evicts a file, a later get() re-reads and re-parses it, returning the
// same function body rather than silently dropping the function (a dropped body
// would leave the candidate unconfirmed, a false negative).
func TestFileParseCacheEvictionReprimes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	f1 := write("f1.c", "int f1(void) {\n    return 1;\n}\n")
	f2 := write("f2.c", "int f2(void) {\n    return 2;\n}\n")
	f3 := write("f3.c", "int f3(void) {\n    return 3;\n}\n")

	p := parser.NewParser()
	defer p.CloseAll()
	p.SetMaxCachedTrees(2)

	cache := newFileParseCache(p)
	defer cache.Close()

	file := func(id int64, path string) *db.File { return &db.File{ID: id, Path: path} }
	fn := func(id, fileID int64) *db.Function { return &db.Function{ID: id, FileID: fileID, StartLine: 1} }

	b1, _ := cache.get(file(1, f1), fn(1, 1))
	if b1.Kind() != "compound_statement" {
		t.Fatalf("file 1 body kind = %q, want compound_statement", b1.Kind())
	}
	b2, _ := cache.get(file(2, f2), fn(2, 2))
	if b2.Kind() != "compound_statement" {
		t.Fatalf("file 2 body kind = %q, want compound_statement", b2.Kind())
	}
	b3, _ := cache.get(file(3, f3), fn(3, 3))
	if b3.Kind() != "compound_statement" {
		t.Fatalf("file 3 body kind = %q, want compound_statement", b3.Kind())
	}

	// The oldest (file 1) must be evicted once three files are pinned.
	if _, ok := cache.trees[1]; ok {
		t.Fatalf("file 1 should have been evicted after priming 3 files with maxEntries=2")
	}

	// Re-priming file 1 must re-read and re-parse it, not drop its body.
	b1Again, _ := cache.get(file(1, f1), fn(1, 1))
	if b1Again.Kind() != "compound_statement" {
		t.Fatalf("re-primed file 1 body kind = %q, want compound_statement", b1Again.Kind())
	}
}
