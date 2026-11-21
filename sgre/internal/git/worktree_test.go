package git

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnclosingWorktree(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if got := EnclosingWorktree(sub); got != root {
		t.Fatalf("EnclosingWorktree(%q) = %q, want %q", sub, got, root)
	}

	file := filepath.Join(sub, "x.c")
	if err := os.WriteFile(file, []byte("int x;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := EnclosingWorktree(file); got != root {
		t.Fatalf("EnclosingWorktree(file %q) = %q, want %q", file, got, root)
	}
}

func TestEnclosingWorktreeFileEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /tmp/wt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "a")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if got := EnclosingWorktree(sub); got != root {
		t.Fatalf("worktree-file entry: EnclosingWorktree(%q) = %q, want %q", sub, got, root)
	}
}

func TestEnclosingWorktreeNone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plain")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if got := EnclosingWorktree(dir); got != "" {
		t.Fatalf("EnclosingWorktree(%q) = %q, want empty", dir, got)
	}
}
