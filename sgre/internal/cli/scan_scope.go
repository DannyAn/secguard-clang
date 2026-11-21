package cli

import (
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/git"
)

// scanScope reports whether a scan is a COMPLETE-PROGRAM scan (the tree defines
// `main`) or a BOUNDARY scan (a library / a subtree), and — when it is a subtree
// of a larger git worktree — names the enclosing worktree.
//
// The distinction is a product fact, not a heuristic: the null-deref seeding
// policy treats every zero-in-tree-caller pointer parameter of a boundary scan
// as fail-open (its callers are outside the tree). Scanning `repo/src` while
// `main` lives in `repo/app` therefore turns the whole module into an external
// boundary and floods the AI with "is this external caller allowed to pass
// NULL?" candidates that are non-null by the project's own convention. The
// pipeline cannot infer that from a subtree, so the scan must SAY it.
func scanScope(targetPath string, funcs []*db.Function) map[string]interface{} {
	hasEntry := false
	for _, f := range funcs {
		if f.Name == "main" {
			hasEntry = true
			break
		}
	}
	worktree := git.EnclosingWorktree(targetPath)
	scope := map[string]interface{}{
		"has_entry_point":    hasEntry,
		"enclosing_worktree": worktree,
	}
	switch {
	case hasEntry:
		scope["mode"] = "complete-program"
	case worktree != "":
		scope["mode"] = "boundary"
		scope["hint"] = "no entry point (main) in the scanned tree and it is a subtree of the git worktree " +
			worktree + " — every boundary pointer parameter is treated as an external caller's argument (fail-open). " +
			"Scan the worktree root for a complete-program result; non-proving fail-open null-deref rows are " +
			"pre-dismissed by default (boundary_auto_dismiss=\"external\"), and \"off\" restores the recall-maximal behaviour."
	default:
		scope["mode"] = "boundary"
		scope["hint"] = "no entry point (main) in the scanned tree — every boundary pointer parameter is treated as an external caller's argument (fail-open). " +
			"Scan the enclosing worktree root for a complete-program result; non-proving fail-open null-deref rows are " +
			"pre-dismissed by default (boundary_auto_dismiss=\"external\"), and \"off\" restores the recall-maximal behaviour."
	}
	return scope
}

// scopeMode / scopeWorktree read one field of the scan-scope map without
// threading the whole map through the report data model.
func scopeMode(scope map[string]interface{}) string {
	if v, ok := scope["mode"].(string); ok {
		return v
	}
	return ""
}

func scopeWorktree(scope map[string]interface{}) string {
	if v, ok := scope["enclosing_worktree"].(string); ok {
		return v
	}
	return ""
}
