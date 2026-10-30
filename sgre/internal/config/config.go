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
	TrustedMacros          TrustedMacros          `toml:"trusted_macros"`
	IteratorMacros         IteratorMacros         `toml:"iterator_macros"`
	BannedFunctions        BannedFunctions        `toml:"banned_functions"`
	Exclude                Exclude                `toml:"exclude"`
	DisabledTypes          DisabledTypes          `toml:"disabled_types"`
	Allocators             Allocators             `toml:"allocators"`
	Deallocators           Deallocators           `toml:"deallocators"`
	SanitizeFunctions      SanitizeFunctions      `toml:"sanitize_functions"`
	OwnershipTransferCalls OwnershipTransferCalls `toml:"ownership_transfer_calls"`
	Nullability            Nullability            `toml:"nullability"`
	IntegerOverflow        IntegerOverflow        `toml:"integer_overflow"`
	Contracts              Contracts              `toml:"contracts"`
	Scan                   Scan                   `toml:"scan"`
	// AIMode is the AI-classification stage switch: "agent" (default) keeps the
	// LLM-orchestrator fan-out; "executor" routes PHASE_2 through the
	// deterministic `secguard classify --mode executor` process.
	AIMode string `toml:"ai_stage_mode"`
}

// Scan tunes whole-scan boundary policy.
type Scan struct {
	// EntryPoints extends the built-in program entry-point set (main /
	// WinMain / wWinMain / DllMain / app_main) with project-specific entry
	// functions (a firmware `thread_entry`, an RTOS task body). A scan tree
	// containing any entry point is treated as a complete program, so
	// boundary parameters stay closed-world instead of failing open.
	//
	//	[scan]
	//	entry_points = ["thread_entry"]
	EntryPoints []string `toml:"entry_points"`
	// BoundaryAutoDismiss controls the boundary-scan fail-open null-deref
	// pre-dismissal layer. A boundary scan (no entry point in the tree) seeds
	// every zero-caller pointer parameter fail-open; those candidates have no
	// in-tree proof and the AI dismisses them. Modes:
	//   "" / "off" (default): no auto-dismiss — a library scan must not
	//     silently drop a possible bug; the boundary report recommends the
	//     explicit `external`/`all` setting below.
	//   "external": auto-dismiss opaque-origin / external-unknown only (the
	//     contract is outside the scan tree); caller-arg / assumed-return keep
	//     an in-tree caller/callee body for the AI.
	//   "all": also auto-dismiss caller-arg / assumed-return (aggressive; only
	//     for a project that accepts the boundary contract as non-null).
	//   "off": no auto-dismiss (pre-0.11.6 behaviour).
	// Every auto-dismissed candidate is still counted in the dismissed ledger
	// under reason `boundary_fail_open`, never silently dropped.
	BoundaryAutoDismiss string `toml:"boundary_auto_dismiss"`
}

// boundaryAutoDismissOverride is the one-shot CLI override
// (`secguard scan --boundary-auto-dismiss external`). It wins over the file so a
// production run can enable the layer without editing secguard.toml.
var boundaryAutoDismissOverride string

// SetBoundaryAutoDismissOverride sets the process-wide CLI override. An empty
// string clears it.
func SetBoundaryAutoDismissOverride(mode string) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "external", "all", "off":
		boundaryAutoDismissOverride = strings.ToLower(strings.TrimSpace(mode))
	default:
		boundaryAutoDismissOverride = ""
	}
}

// BoundaryAutoDismissMode normalizes the configured mode.
func (c *Config) BoundaryAutoDismissMode() string {
	if boundaryAutoDismissOverride != "" {
		return boundaryAutoDismissOverride
	}
	if c == nil {
		return "off"
	}
	switch strings.ToLower(strings.TrimSpace(c.Scan.BoundaryAutoDismiss)) {
	case "external":
		return "external"
	case "all":
		return "all"
	default:
		return "off"
	}
}

type TrustedMacros struct {
	// Names are function-like macros whose expansion computes a pointer from a
	// memory address (field + offset arithmetic) rather than a possibly-null
	// allocation/lookup result. Callers dereference the result without a null
	// check by contract, so these names never seed a null source.
	Names []string `toml:"names"`
}

// BannedFunctions tunes the built-in dangerous-function policy table (CWE-676).
// The built-in table (process/thread exit, alloca, setjmp/longjmp, the non-`_s`
// mem/str/format/scan families, atoi-family, realloc, assert, and the
// obsolete/insecure APIs) is a DEFAULT policy, not the project's authoritative
// list. `names` ADDS project-specific bans (category "config_banned", e.g. a
// wrapper the project deprecated); `exclude` REMOVES named built-ins so a
// project whose own security guideline does not ban a function never sees the
// finding (e.g. the deprecated BSD bzero/bcopy/bcmp trio once the project's
// guideline omits it). `exclude` wins when a name appears in both lists.
//
//	[banned_functions]
//	names   = ["my_legacy_alloc"]
//	exclude = ["realloc", "mktemp"]
type BannedFunctions struct {
	Names   []string `toml:"names"`
	Exclude []string `toml:"exclude"`
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

// SanitizeFunctions declares project-specific functions whose return value is
// a directory-free (sanitized) copy of their argument's path content — the
// basename-family contract. The path-traversal convergence treats an
// assignment from such a call as killing the target's path taint, so
// `seg = my_sanitize(p); unlink(seg);` is dropped instead of surfacing as a
// candidate the AI must dismiss. Builtin basename is always recognized;
// strrchr/rindex are recognized only with a '/' separator.
//
//	[sanitize_functions]
//	names = ["my_basename_wrapper"]
type SanitizeFunctions struct {
	Names []string `toml:"names"`
}

// OwnershipTransferCalls declares project-specific functions that take
// ownership of a pointer argument (the callee now owns and will release it).
// The memory/resource leak detectors treat a pointer passed to such a call as
// escaped, not leaked. Typical entries are container insert helpers
// (list_push_back, dict_set, buffer_append) whose naming does not match the
// built-in IsEscapeFunction heuristic (_put/_push/_add/...), and error-handling
// or comm framework functions that free the message/path they receive
// (fail, fail_nc_err, transapi_comm_with_vrp) when the built-in
// directly-returned + unused-afterwards shape does not already cover the call
// site (e.g. the call is stored, not returned).
//
//	[ownership_transfer_calls]
//	names = ["list_push_back", "dict_set", "buffer_append"]
type OwnershipTransferCalls struct {
	Names []string `toml:"names"`
}

// Nullability declares function return-value nullability for third-party
// functions whose definitions live outside the scan tree. This is the
// "never-null return" tier: functions with an abort-on-failure contract
// (xmalloc, g_malloc, sdsnew, ...) that never return NULL, so a dereference
// of their result is never a null-deref.
//
//	[nullability.non_null_returns]
//	names = ["xmalloc", "g_malloc", "g_new", "sdsnew"]
//
// NonNullParams is the PARAMETER-side equivalent: names of pointer parameters
// whose value is guaranteed non-null by an out-of-tree framework contract (a
// data-plane callback's user_data, an IPC/CLI dispatcher's msg/reply_msg
// output slots). In a BOUNDARY scan (a subtree with no entry point) every
// zero-in-caller pointer parameter is otherwise treated as an external
// caller's argument (fail-open), which is the single largest source of
// null-deref contract candidates. Declaring the name here suppresses only that
// ASSUMPTION; a call site that demonstrably passes a literal NULL still
// surfaces (evidence beats the declaration — and contradicts it).
//
//	[nullability.non_null_params]
//	names = ["user_data", "sync_data", "reply_msg", "out_msg"]
type Nullability struct {
	NonNullReturns NonNullReturns `toml:"non_null_returns"`
	NonNullParams  NonNullParams  `toml:"non_null_params"`
}

// NonNullReturns declares function names whose return value is guaranteed
// non-null. The null source detector skips these instead of seeding a false
// null source.
type NonNullReturns struct {
	Names []string `toml:"names"`
}

// NonNullParams declares pointer PARAMETER names that are non-null by an
// external framework contract. The caller-null detector does not seed the
// boundary fail-open assumption for them.
type NonNullParams struct {
	Names []string `toml:"names"`
}

// IntegerOverflow declares project-specific facts that sharpen the
// integer-overflow convergence. TruncatingWrappers lists functions whose return
// value is bounded by one of their arguments (the capacity/size argument), so an
// accumulator built from their returns stays within the buffer and a later
// `size - length` subtraction cannot underflow.
//
//	[integer_overflow.truncating_wrappers]
//	nlog_syslog_add_pri      = 1   # return <= arg 1 (the buffer size)
//	nlog_syslog_add_hostname = 1
type IntegerOverflow struct {
	TruncatingWrappers map[string]int `toml:"truncating_wrappers"`
}

// Contracts declares contracts for tree-EXTERNAL symbols (framework/SDK
// functions or macros whose definitions live outside the scan tree), so the AI
// classifier judges a call to them from the declared contract instead of
// deep-diving a body the scan cannot see. Each entry maps a symbol name to its
// contract; the symbol is matched against a candidate's callee (api@), and the
// contract is injected into the candidate Hint as decisive, no-open facts.
//
//	[contracts]
//	"framework_send_data" = { takes_ownership = "param-1", releases = "on-success" }
//	"vendor_hton_buf"     = { out_params = ["param-4"] }
type Contracts struct {
	BySymbol map[string]Contract `toml:"-"`
}

// UnmarshalTOML lets `[contracts]` be a bare map of symbol -> inline contract,
// so users write the compact `[contracts]` table above rather than a nested
// `[contracts.by_symbol.<name>]` form.
func (c *Contracts) UnmarshalTOML(v interface{}) error {
	raw, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	c.BySymbol = make(map[string]Contract, len(raw))
	for sym, val := range raw {
		// Accept either a string (a marker with no semantics yet) or an inline
		// table carrying the contract fields.
		switch t := val.(type) {
		case string:
			c.BySymbol[sym] = Contract{Note: t}
		case map[string]interface{}:
			var ct Contract
			if s, ok := t["takes_ownership"].(string); ok {
				ct.TakesOwnership = s
			}
			if s, ok := t["releases"].(string); ok {
				ct.Releases = s
			}
			if arr, ok := t["out_params"].([]interface{}); ok {
				for _, e := range arr {
					if s, ok := e.(string); ok {
						ct.OutParams = append(ct.OutParams, s)
					}
				}
			}
			c.BySymbol[sym] = ct
		}
	}
	return nil
}

// Contract is one tree-external symbol's declared semantics. Field values use
// the parameter spelling the user writes (`param-1`, `param-4`) — they are
// rendered verbatim into the candidate Hint, not normalized to indices.
type Contract struct {
	// TakesOwnership names the parameter the callee takes ownership of (the
	// caller must NOT release it afterward).
	TakesOwnership string `toml:"takes_ownership"`
	// Releases describes when the callee releases an owned resource
	// (on-success / on-error / always).
	Releases string `toml:"releases"`
	// OutParams lists the parameters the callee writes through (output params).
	OutParams []string `toml:"out_params"`
	// Note is a free-form annotation accepted when the user writes a bare string
	// instead of an inline table.
	Note string `toml:"note"`
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
// Load returns the effective configuration. A missing optional config still
// degrades to the zero Config silently (a nil config file is not an error);
// a config that was located but cannot be read or parsed is logged to stderr
// so a mistyped secguard.toml never silently disables every detector setting
// (the historical "secguard.toml written to the project root instead of
// .codeagent/" failure mode).
//
// CLI startup should call LoadE and treat a read/parse error as fatal; Load
// is kept for detectors / planners that do not have an error channel.
func Load() *Config {
	cfg, err := LoadE()
	if err != nil {
		fmt.Fprintf(os.Stderr, "secguard: config load warning: %v (using zero config)\n", err)
	}
	return cfg
}

// LoadE is the checked variant of Load. A missing optional config is still not
// an error; a resolved path that cannot be read or parsed is.
func LoadE() (*Config, error) {
	cfg := &Config{}
	path := resolvePath(explicitPath)
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// A path resolved from an explicit --config / SECGUARD_CONFIG (or a
		// probed default that existed a moment ago) must not fail silently: a
		// zero config evaporates the banned-function / trusted-macro / disable
		// settings with no trace. Missing-file fallback is handled by resolvePath
		// returning "" BEFORE we get here, so a read error here is unexpected.
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	// A malformed or mistyped config must not be silently ignored: the user would
	// get a "seems to load" config whose trusted-macro allowlist silently
	// disappears. Load() has no error channel (the file is optional and a missing
	// file is not an error), so surface parse failures on stderr and keep the
	// zero config rather than a half-populated one.
	if err := toml.Unmarshal(data, cfg); err != nil {
		return &Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// TrustedMacroNames returns the configured trusted-macro allowlist.
func (c *Config) TrustedMacroNames() []string {
	if c == nil {
		return nil
	}
	return c.TrustedMacros.Names
}

// BannedFunctionNames returns the project-specific banned-function list to merge
// with the built-in dangerous/obsolete set (CWE-676).
func (c *Config) BannedFunctionNames() []string {
	if c == nil {
		return nil
	}
	return c.BannedFunctions.Names
}

// BannedFunctionExcludeNames returns the built-in policy names the project
// removes: its own security guideline is the authority on which functions are
// banned, so a built-in the guideline does not list must not be reported.
func (c *Config) BannedFunctionExcludeNames() []string {
	if c == nil {
		return nil
	}
	return c.BannedFunctions.Exclude
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

// defaultEntryPoints are the platform entry-point names that always mark the
// scan tree as a complete program.
var defaultEntryPoints = []string{"main", "WinMain", "wWinMain", "DllMain", "app_main"}

// EntryPointNames returns the built-in entry-point set merged with the
// project-specific `[scan].entry_points`.
func (c *Config) EntryPointNames() []string {
	names := append([]string{}, defaultEntryPoints...)
	if c == nil {
		return names
	}
	return append(names, c.Scan.EntryPoints...)
}

// SanitizeFunctionNames returns the project-specific path-sanitizer names
// (functions returning a directory-free copy of their argument), registered
// into apikb at CLI startup so the path-traversal convergence treats an
// assignment from them as killing the target's path taint.
func (c *Config) SanitizeFunctionNames() []string {
	if c == nil {
		return nil
	}
	return c.SanitizeFunctions.Names
}

// NonNullReturnNames returns the project-specific never-null return function
// names. These are registered into apikb at CLI startup so the null source
// detector skips them instead of seeding a false null source.
func (c *Config) NonNullReturnNames() []string {
	if c == nil {
		return nil
	}
	return c.Nullability.NonNullReturns.Names
}

// NonNullParamNames returns the project-specific pointer-parameter names that
// are non-null by an external framework contract. Registered into apikb at CLI
// startup so the caller-null detector does not seed the boundary fail-open
// assumption for them.
func (c *Config) NonNullParamNames() []string {
	if c == nil {
		return nil
	}
	return c.Nullability.NonNullParams.Names
}

// OwnershipTransferCallNames returns the project-specific ownership-transfer
// function names. These are registered into apikb at CLI startup so the leak
// detectors treat a pointer passed to them as escaped, not leaked.
func (c *Config) OwnershipTransferCallNames() []string {
	if c == nil {
		return nil
	}
	return c.OwnershipTransferCalls.Names
}

// IntegerOverflowTruncatingWrappers returns the project-specific truncating
// wrappers (function name -> 0-based capacity argument index) declared in
// secguard.toml. These are registered into apikb at CLI startup so the
// integer-overflow detector can prove an accumulator built from them stays
// bounded by the buffer size.
func (c *Config) IntegerOverflowTruncatingWrappers() map[string]int {
	if c == nil {
		return nil
	}
	return c.IntegerOverflow.TruncatingWrappers
}

// ContractBySymbol returns the user-declared tree-external contracts (symbol ->
// contract). A nil config or an empty [contracts] table returns an empty map.
func (c *Config) ContractBySymbol() map[string]Contract {
	if c == nil || c.Contracts.BySymbol == nil {
		return map[string]Contract{}
	}
	return c.Contracts.BySymbol
}

// AIStageMode returns the normalized AI-classification stage mode ("agent"
// default, or "executor").
func (c *Config) AIStageMode() string {
	if c == nil {
		return "agent"
	}
	switch strings.ToLower(strings.TrimSpace(c.AIMode)) {
	case "executor":
		return "executor"
	default:
		return "agent"
	}
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
