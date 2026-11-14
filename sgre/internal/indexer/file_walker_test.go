package indexer

import (
	"os"
	"path/filepath"
	"syscall"
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

// A .c symlink pointing outside the scan root must be skipped: filepath.Walk
// surfaces it (Lstat), but a later ReadFile would follow it and leak host file
// content into the report (issue #275 P1-3).
func TestWalkCFiles_SkipsSymlinkAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-secret.c")
	if err := os.WriteFile(outside, []byte("int secret;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "real.c")

	if err := os.Symlink(outside, filepath.Join(root, "leak.c")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	// A FIFO must not be picked up either (reading it would block the scan).
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.c"), 0600); err != nil {
		// Mkfifo may be unavailable; the symlink half of the test still holds.
		t.Logf("mkfifo skipped: %v", err)
	}

	got := walkedRelPaths(t, root, nil)

	if !got["real.c"] {
		t.Error("real.c should be indexed")
	}
	if got["leak.c"] {
		t.Error("a .c symlink pointing outside the root must not be indexed")
	}
	if got["pipe.c"] {
		t.Error("a FIFO must not be indexed")
	}
}
