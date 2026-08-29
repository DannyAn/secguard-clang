// Package config loads the optional secguard.toml configuration. The file is
// optional and platform-located, so a user's trusted-macro allowlist (which may
// contain environment-specific names) lives OUTSIDE the shipped extension and
// survives uninstall/reinstall.
package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config is the secguard.toml structure. Fields are additive and optional; a
// missing file yields the zero Config with no error.
type Config struct {
	TrustedMacros TrustedMacros `toml:"trusted_macros"`
}

type TrustedMacros struct {
	// Names are function-like macros whose expansion computes a pointer from a
	// memory address (field + offset arithmetic) rather than a possibly-null
	// allocation/lookup result. Callers dereference the result without a null
	// check by contract, so these names never seed a null source.
	Names []string `toml:"names"`
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
	_ = toml.Unmarshal(data, cfg)
	return cfg
}

// TrustedMacroNames returns the configured trusted-macro allowlist.
func (c *Config) TrustedMacroNames() []string {
	if c == nil {
		return nil
	}
	return c.TrustedMacros.Names
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
