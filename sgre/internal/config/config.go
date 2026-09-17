// Package config loads the optional secguard.toml configuration. The file is
// optional and platform-located, so a user's trusted-macro allowlist (which may
// contain environment-specific names) lives OUTSIDE the shipped extension and
// survives uninstall/reinstall.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/DannyAn/secguard-clang/internal/apikb"
)

// Config is the secguard.toml structure. Fields are additive and optional; a
// missing file yields the zero Config with no error.
type Config struct {
	TrustedMacros   TrustedMacros   `toml:"trusted_macros"`
	IteratorMacros  IteratorMacros  `toml:"iterator_macros"`
	BannedFunctions BannedFunctions `toml:"banned_functions"`
	Exclude         Exclude         `toml:"exclude"`
	DisabledTypes   DisabledTypes   `toml:"disabled_types"`
	Allocators      Allocators      `toml:"allocators"`
	Deallocators    Deallocators    `toml:"deallocators"`
}

type TrustedMacros struct {
	// Names are function-like macros whose expansion computes a pointer from a
	// memory address (field + offset arithmetic) rather than a possibly-null
	// allocation/lookup result. Callers dereference the result without a null
	// check by contract, so these names never seed a null source.
	Names []string `toml:"names"`
}

// BannedFunctions extends the built-in dangerous/obsolete function list
// (CWE-676) with project-specific bans. The built-in list is always active;
// this section only ADDS names, so an enterprise can ban a function the default
// list does not (e.g. a wrapper it has deprecated).
//
//	[banned_functions]
//	names = ["strcpy", "my_legacy_alloc"]
type BannedFunctions struct {
	Names []string `toml:"names"`
}

// Allocators declares project-specific allocation functions so the memory
// detectors treat them like malloc (their result may be NULL and must be
// released). Typical entries are allocation wrappers (nat_malloc) or SDK macros
// (VOS_MALLOC/VOS_MALLOC_F) whose definitions live outside the scan tree.
//
//	[allocators]
//	names = ["nat_malloc", "llm_malloc", "VOS_MALLOC", "VOS_MALLOC_F"]
type Allocators struct {
	Names []string `toml:"names"`
}

// Deallocators declares project-specific release functions so the memory
// detectors treat them like free. Typical entries are release wrappers
// (nat_free) or SDK macros (VOS_FREE/VOS_FREE_F) defined outside the scan tree.
//
//	[deallocators]
//	names = ["nat_free", "llm_free", "VOS_FREE", "VOS_FREE_F"]
type Deallocators struct {
	Names []string `toml:"names"`
}

// DisabledTypes declares vulnerability types to turn OFF for the whole scan. A
// disabled type produces no candidates — the convergence plan stage never runs
// for it, so the AI agent's skills never receive it. This is the type switch for
// noisy/slow types (e.g. path-traversal, divide-by-zero): it removes them from
// the scan result AND from the end-to-end wall-clock, not merely from the final
// report.
//
//	[disabled_types]
//	types = ["path-traversal", "divide-by-zero"]
type DisabledTypes struct {
	// Types are kebab-case vulnerability-type names (matching `secguard types`).
	Types []string `toml:"types"`
}

// Exclude declares directory trees to skip during indexing. Paths are resolved
// against the SCAN TARGET (the <path> argument, e.g. `secguard scan ./src`), so
// a relative entry like "svc/src/bak" excludes <target>/svc/src/bak — never a
// path relative to the current working directory or the config file location.
//
//	[exclude]
//	paths = ["./svc/src/bak/", "src/generated"]
type Exclude struct {
	// Paths are directory paths to prune entirely during the file walk. Each
	// entry may be relative to the scan target or absolute; a trailing slash is
	// ignored. Unlike the --exclude flag (which matches directory BASENAMES),
	// these match the full path, so two directories both named "bak" can be
	// treated differently.
	Paths []string `toml:"paths"`
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
		// A path resolved from an explicit --config / SECGUARD_CONFIG (or a
		// probed default that existed a moment ago) must not fail silently: a
		// zero config evaporates the banned-function / trusted-macro / disable
		// settings with no trace. Missing-file fallback is handled by resolvePath
		// returning "" BEFORE we get here, so a read error here is unexpected.
		fmt.Fprintf(os.Stderr, "secguard: ignoring unreadable config %s: %v\n", path, err)
		return cfg
	}
	// A malformed or mistyped config must not be silently ignored: the user would
	// get a "seems to load" config whose trusted-macro allowlist silently
	// disappears. Load() has no error channel (the file is optional and a missing
	// file is not an error), so surface parse failures on stderr and keep the
	// zero config rather than a half-populated one.
	if err := toml.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "secguard: ignoring invalid config %s: %v\n", path, err)
		return &Config{}
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

// BannedFunctionNames returns the project-specific banned-function list to merge
// with the built-in dangerous/obsolete set (CWE-676). The built-in list is
// always active; these names only extend it.
func (c *Config) BannedFunctionNames() []string {
	if c == nil {
		return nil
	}
	return c.BannedFunctions.Names
}

// AllocatorNames returns the project-specific allocation-function names.
func (c *Config) AllocatorNames() []string {
	if c == nil {
		return nil
	}
	return c.Allocators.Names
}

// DeallocatorNames returns the project-specific release-function names.
func (c *Config) DeallocatorNames() []string {
	if c == nil {
		return nil
	}
	return c.Deallocators.Names
}

// ExcludePaths returns the configured directory paths to prune during indexing.
// The entries are returned raw (relative paths are NOT resolved here): the
// indexer resolves them against the scan target because only it knows the root.
func (c *Config) ExcludePaths() []string {
	if c == nil {
		return nil
	}
	return c.Exclude.Paths
}

// DisabledTypeNames returns the configured type-switch names (kebab-case
// vulnerability types), trimmed of surrounding whitespace and de-duplicated in
// declaration order.
func (c *Config) DisabledTypeNames() []string {
	if c == nil {
		return nil
	}
	seen := make(map[string]bool, len(c.DisabledTypes.Types))
	out := make([]string, 0, len(c.DisabledTypes.Types))
	for _, n := range c.DisabledTypes.Types {
		if t := strings.TrimSpace(n); t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// DisabledTypeSet returns the disabled type names as a set, for O(1) lookups
// when filtering the vuln-type list. A nil/empty set means "nothing disabled".
func (c *Config) DisabledTypeSet() map[string]bool {
	names := c.DisabledTypeNames()
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
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

// MergedIteratorMacros combines the built-in iterator-macro knowledge base
// (apikb.IteratorMacros, covering standard list_for_each_entry & friends) with
// the project-specific macros declared in secguard.toml [iterator_macros]. It is
// the single merge point consumed by both the null-deref/uninit flow filters and
// the uninit detector, so the two layers can never disagree on which parameter a
// macro writes.
func (c *Config) MergedIteratorMacros() map[string][]int {
	out := make(map[string][]int, len(apikb.IteratorMacros))
	for k, v := range apikb.IteratorMacros {
		out[k] = v
	}
	for k, v := range c.IteratorMacroArgs() {
		out[k] = v
	}
	return out
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
	info, err := os.Stat(p)
	// A directory named secguard.toml would pass a bare Stat and then fail the
	// subsequent ReadFile (EISDIR); exclude it so the probe falls through to the
	// next location instead of silently reading nothing.
	return err == nil && !info.IsDir()
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}
