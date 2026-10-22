package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestScanScopeBoundarySubtreeNamesWorktree(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "src")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	scope := scanScope(sub, []*db.Function{{Name: "helper"}})
	if scope["mode"] != "boundary" {
		t.Fatalf("mode = %v, want boundary (no main)", scope["mode"])
	}
	if scope["enclosing_worktree"] != root {
		t.Fatalf("enclosing_worktree = %v, want %s", scope["enclosing_worktree"], root)
	}
	if scope["hint"] == nil {
		t.Fatalf("a subtree boundary scan must explain the fail-open consequence")
	}
}

func TestScanScopeCompleteProgram(t *testing.T) {
	root := t.TempDir()
	scope := scanScope(root, []*db.Function{{Name: "main"}, {Name: "helper"}})
	if scope["mode"] != "complete-program" {
		t.Fatalf("mode = %v, want complete-program", scope["mode"])
	}
}
