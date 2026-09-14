package indexer

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("int x;\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func walkedRelPaths(t *testing.T, root string, paths []string) map[string]bool {
	t.Helper()
	files, err := WalkCFiles(root, nil, paths, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range files {
		rel, err := filepath.Rel(root, f)
		if err != nil {
			t.Fatal(err)
		}
		got[filepath.ToSlash(rel)] = true
	}
	return got
}

func TestWalkCFiles_ExcludePathRelativeToRoot(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, filepath.Join("svc", "src", "bak", "keep.c"))
	writeTestFile(t, root, filepath.Join("svc", "src", "main.c"))
	writeTestFile(t, root, filepath.Join("other", "bak", "keep.c"))

	got := walkedRelPaths(t, root, []string{filepath.Join("svc", "src", "bak")})

	// The configured path (relative to the scan target) is pruned entirely; a
	// same-named directory elsewhere is NOT pruned (path match, not basename).
	if got["svc/src/bak/keep.c"] {
		t.Error("svc/src/bak/keep.c should be excluded by path")
	}
	if !got["svc/src/main.c"] {
		t.Error("svc/src/main.c should be indexed")
	}
	if !got["other/bak/keep.c"] {
		t.Error("other/bak/keep.c should be indexed (basename bak is not a default exclude)")
	}
}

func TestWalkCFiles_ExcludePathWithTrailingSlashAndDot(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, filepath.Join("svc", "src", "bak", "keep.c"))
	writeTestFile(t, root, filepath.Join("svc", "src", "main.c"))

	// "./svc/src/bak/" — the form a user writes in secguard.toml — must resolve
	// to <root>/svc/src/bak and prune it.
	got := walkedRelPaths(t, root, []string{"./svc/src/bak/"})

	if got["svc/src/bak/keep.c"] {
		t.Error("svc/src/bak/keep.c should be excluded")
	}
	if !got["svc/src/main.c"] {
		t.Error("svc/src/main.c should be indexed")
	}
}

func TestWalkCFiles_ExcludePathAbsolute(t *testing.T) {
	root := t.TempDir()
	absBak := filepath.Join(root, "svc", "src", "bak")
	writeTestFile(t, root, filepath.Join("svc", "src", "bak", "keep.c"))
	writeTestFile(t, root, filepath.Join("svc", "src", "main.c"))

	got := walkedRelPaths(t, root, []string{absBak})

	if got["svc/src/bak/keep.c"] {
		t.Error("svc/src/bak/keep.c should be excluded by absolute path")
	}
	if !got["svc/src/main.c"] {
		t.Error("svc/src/main.c should be indexed")
	}
}
