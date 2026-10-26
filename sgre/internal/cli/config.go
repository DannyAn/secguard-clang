package cli

import (
	"os"

	"github.com/DannyAn/secguard-clang/internal/config"
)

// runConfigCmd reports the effective secguard.toml configuration so a user can
// discover, at runtime, where to put settings and what is currently active. The
// file is optional and self-describing; this command is the entry point that
// makes it discoverable without reading the docs.
func runConfigCmd(args []string) int {
	if hasHelpFlag(args) {
		printConfigUsage()
		return 0
	}
	if hasFlag(args, "example") {
		printConfigExample()
		return 0
	}

	cfg := config.Load()
	path := config.ResolvedPath()
	loaded := false
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			loaded = true
		}
	}
	out := map[string]interface{}{
		"path":                     path,
		"loaded":                   loaded,
		"trusted_macros":           cfg.TrustedMacroNames(),
		"iterator_macros":          cfg.IteratorMacroArgs(),
		"banned_functions":         cfg.BannedFunctionNames(),
		"banned_functions_exclude": cfg.BannedFunctionExcludeNames(),
		"exclude_paths":            cfg.ExcludePaths(),
		"disabled_types":           cfg.DisabledTypeNames(),
		"non_null_returns":         cfg.NonNullReturnNames(),
		"non_null_params":          cfg.NonNullParamNames(),
		"entry_points":             cfg.EntryPointNames(),
		"note":                     "run 'secguard config --help' for the full reference, 'secguard config --example' for a copy-paste template",
	}
	_ = WriteJSON(out)
	return 0
}
