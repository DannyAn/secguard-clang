package git

import (
	"os"
	"path/filepath"
)

// EnclosingWorktree walks up from path and returns the first ancestor carrying
// a `.git` entry (a directory, or a file for worktrees/submodules), or "" when
// path is not inside a git worktree. A file target is resolved to its directory
// first.
func EnclosingWorktree(path string) string {
	dir, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
