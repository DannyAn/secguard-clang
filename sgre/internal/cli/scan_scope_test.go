package cli

import (
	"os"
	"path/filepath"
	"strings"
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

func TestWriteBoundaryConfigHint(t *testing.T) {
	dir := t.TempDir()
	writeBoundaryConfigHint(dir, "/repo/src", "/repo")
	data, err := os.ReadFile(filepath.Join(dir, "secguard.toml.suggested"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"boundary_auto_dismiss", "entry_points", "non_null_params", "secguard scan /repo"} {
		if !strings.Contains(text, want) {
			t.Errorf("boundary config hint missing %q:\n%s", want, text)
		}
	}
}
