// Package config loads the optional secguard.toml configuration. The file is
// optional and platform-located, so a user's trusted-macro allowlist (which may
// contain environment-specific names) lives OUTSIDE the shipped extension and
// survives uninstall/reinstall.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config is the secguard.toml structure. Fields are additive and optional; a
// missing file yields the zero Config with no error.
type Config struct {
	TrustedMacros  TrustedMacros  `toml:"trusted_macros"`
	IteratorMacros IteratorMacros `toml:"iterator_macros"`
}

type TrustedMacros struct {
	// Names are function-like macros whose expansion computes a pointer from a
	// memory address (field + offset arithmetic) rather than a possibly-null
	// allocation/lookup result. Callers dereference the result without a null
	// check by contract, so these names never seed a null source.
	Names []string `toml:"names"`
}

// IteratorMacros declares project-specific iterator macros whose definitions
// live outside the scan tree (e.g. an SDK header). Each entry maps a macro name
// to the 0-based indices of its iterator parameter(s) — the parameter(s)
// written in the for-init clause and null-guarded by the loop condition, so the
// iterator is provably non-null on every path reaching the loop body.
//
// Example: SAMPLE_Scan(list, iter, type) writes `iter` (index 1):
//
//	[iterator_macros.macros]
//	SAMPLE_Scan = [1]
type IteratorMacros struct {
	// Macros maps macro name to the 0-based indices of its iterator parameter(s).
	Macros map[string][]int `toml:"macros"`
}

// explicitPath is set by the CLI layer from the --config flag. It takes
// precedence over the env var and the default paths.
var explicitPath string

// SetExplicitPath records the --config flag value (called once at CLI startup).
func SetExplicitPath(path string) {
	explicitPath = path
}

// Load resolves the config file, in priority order:
//
//  1. --config flag (via SetExplicitPath)
//  2. SECGUARD_CONFIG env var
//  3. project-level  <cwd>/.codeagent/secguard.toml   (per-repo exceptions)
//  4. user-level     ~/.codeagent/secguard.toml       (personal default)
//
// A missing file is not an error: the caller falls back to built-in behavior.
// Both default locations share the .codeagent naming, consistent with the
// runtime data dir (.codeagent/secguard-clang/).
func Load() *Config {
	cfg := &Config{}
	path := resolvePath(explicitPath)
	if path == "" {
		return cfg
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	// A malformed or mistyped config must not be silently ignored: the user would
	// get a "seems to load" config whose trusted-macro allowlist silently
	// disappears. Load() has no error channel (the file is optional and a missing
	// file is not an error), so surface parse failures on stderr and keep the
	// zero config rather than a half-populated one.
	if err := toml.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "secguard: ignoring invalid config %s: %v\n", path, err)
	}
	return cfg
}

// TrustedMacroNames returns the configured trusted-macro allowlist.
func (c *Config) TrustedMacroNames() []string {
	if c == nil {
		return nil
	}
	return c.TrustedMacros.Names
}

// IteratorMacroArgs returns the configured iterator-macro map (macro name →
// 0-based iterator parameter indices). It merges with the built-in
// apikb.IteratorMacros table at planner startup.
func (c *Config) IteratorMacroArgs() map[string][]int {
	if c == nil {
		return nil
	}
	return c.IteratorMacros.Macros
}

// ResolvedPath returns the config file path Load() would read, in the same
// priority order (--config > SECGUARD_CONFIG > project > user), or "" when no
// config file is active. It is the runtime answer to "where do I put settings",
// surfaced by `secguard config` so a user never has to guess the location.
func ResolvedPath() string {
	return resolvePath(explicitPath)
}

func resolvePath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("SECGUARD_CONFIG"); env != "" {
		return env
	}
	// Project-level (per-repo exceptions) wins over user-level.
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		if p := filepath.Join(cwd, ".codeagent", "secguard.toml"); fileExists(p) {
			return p
		}
	}
	if h := homeDir(); h != "" {
		if p := filepath.Join(h, ".codeagent", "secguard.toml"); fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}
