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
	Uninit                 Uninit                 `toml:"uninit"`
	Contracts              Contracts              `toml:"contracts"`
	Scan                   Scan                   `toml:"scan"`
	Severity               Severity               `toml:"severity"`
	Switch                 Switch                 `toml:"switch"`
	Graph                  Graph                  `toml:"graph"`
	// AIMode is the AI-classification stage switch: "agent" (default) keeps the
	// LLM-orchestrator fan-out; "executor" routes PHASE_2 through the
	// deterministic `secguard classify --mode executor` process.
	AIMode string `toml:"ai_stage_mode"`
}

// Switch tunes the switch-fallthrough detector's vocabulary. A deployment that
// uses a non-GCC fallthrough marker (e.g. a project `FALLTHRU` macro) or a
// custom noreturn helper extends the built-ins here instead of editing source.
type Switch struct {
	// FallthroughMarkers extends the GCC-recognized intentional-fallthrough
	// comment spellings (case-insensitive).
	FallthroughMarkers []string `toml:"fallthrough_markers"`
	// NoreturnFunctions extends the built-in noreturn call set that terminates a
	// case body (longjmp / __builtin_trap / __builtin_unreachable).
	NoreturnFunctions []string `toml:"noreturn_functions"`
}

// MergedFallthroughMarkers returns the built-in fallthrough spellings plus the
// configured additions.
func (c *Config) MergedFallthroughMarkers() []string {
	return append([]string{"fall through", "fallthrough", "falls through", "fallthru", "fall-through"}, c.Switch.FallthroughMarkers...)
}

// MergedNoreturnFunctions returns the built-in noreturn call names plus the
// configured additions.
func (c *Config) MergedNoreturnFunctions() map[string]bool {
	out := map[string]bool{"longjmp": true, "__builtin_trap": true, "__builtin_unreachable": true}
	for _, name := range c.Switch.NoreturnFunctions {
		out[name] = true
	}
	return out
}

// Graph tunes the semantic-graph builders.
type Graph struct {
	// IndirectCallResolution enables the function-pointer / ops-table indirect
	// CALL edge resolution (FuncPtrWriteBuilder). Default true.
	IndirectCallResolution *bool `toml:"indirect_call_resolution"`
}

// IndirectCallResolutionEnabled reports whether func-ptr indirect CALL edges are
// built (default true).
func (c *Config) IndirectCallResolutionEnabled() bool {
	return c.Graph.IndirectCallResolution == nil || *c.Graph.IndirectCallResolution
}

// Severity carries the user's explicit severity-scale overrides. A user who
// disagrees with a type's default (e.g. null-deref as MEDIUM) pins it here; the
// override is a documented decision and is NOT asserted by the SKILL-frontmatter
// guard (which checks only the registry default).
type Severity struct {
	// Overrides maps a vuln type (or "type.category" / "category") to a severity.
	//	[severity.overrides]
	//	"null-deref" = "high"
	Overrides map[string]string `toml:"overrides"`
}

// SeverityOverrides returns the configured severity overrides (empty map when
// none are set).
func (c *Config) SeverityOverrides() map[string]string {
	if c.Severity.Overrides == nil {
		return map[string]string{}
	}
	return c.Severity.Overrides
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
	// in-tree proof and production triage dismisses almost all of them
	// (0 confirmed out of 262 fail-open rows, ~99% of the AI wall-clock).
	// Modes:
	//   "" / "external" (default): auto-dismiss every NON-PROVING origin tier —
	//     opaque-origin, external-unknown, callback-entry, assumed-return, and
	//     caller-arg rooted at an unguarded external entry (zero in-tree call
	//     sites). These are fail-open ASSUMPTIONS, not evidence. A candidate
	//     with a concrete in-tree caller-null witness (a caller that passes
	//     NULL or forwards an open parameter) is kept for the AI.
	//     Every dismissal is ledgered under `boundary_fail_open` (visible, never
	//     silently dropped), and the boundary report recommends scanning the
	//     worktree root for a complete-program judgment.
	//   "all": also auto-dismiss caller-arg forwarding hops (aggressive; only for
	//     a project that accepts the boundary contract as non-null).
	//   "off": no auto-dismiss (pre-0.11.6 behaviour) — every fail-open row goes
	//     to the AI. This is the recall-maximal escape hatch.
	BoundaryAutoDismiss string `toml:"boundary_auto_dismiss"`
	// CompileCommands is the compile_commands.json path (GAP-03). When empty, the
	// pipeline auto-detects <target>/compile_commands.json then
	// <target>/build/compile_commands.json; the --compile-commands flag wins over
	// this config.
	CompileCommands string `toml:"compile_commands"`
	// SkipDetectors names evidence detectors to turn OFF for the whole scan. It
	// is the detector-stage twin of [disabled_types]: some detectors cost a lot
	// and contribute nothing on a given codebase (production: unchecked_return
	// burned 20s for 0 candidates), so a repo opts out of that stage without
	// editing source. A skipped detector emits no events, so its downstream
	// vulnerability types converge to 0 candidates — the skipped set is recorded
	// in the scan result so "0" is never mistaken for "clean".
	//
	//	[scan]
	//	skip_detectors = ["unchecked_return", "memory_leak"]
	SkipDetectors []string `toml:"skip_detectors"`
	// GraphBuildersConcurrency caps the number of graph builders that run in
	// parallel. Default 7 (one per builder). Lowering it trades wall-clock for
	// peak memory on large repos where 7 parallel tree walks compete for RSS.
	//	[scan]
	//	graph_builders_concurrency = 4
	GraphBuildersConcurrency int `toml:"graph_builders_concurrency"`
	// PlanConcurrency caps the number of vuln-type plan goroutines. Default 8.
	//	[scan]
	//	plan_concurrency = 4
	PlanConcurrency int `toml:"plan_concurrency"`
	// DetectorConcurrency caps the number of detectors that run in parallel.
	// Default 8.
	//	[scan]
	//	detector_concurrency = 4
	DetectorConcurrency int `toml:"detector_concurrency"`
	// CFGCacheMaxEntries bounds the per-scan statement-CFG cache by entry
	// count. 0 = default 4000; a negative value keeps the legacy unbounded
	// mode. The LRU evicts only entries with no live CFGLease.
	//	[scan]
	//	cfg_cache_max_entries = 1000
	CFGCacheMaxEntries int `toml:"cfg_cache_max_entries"`
	// CFGCacheMaxTotalNodes bounds the CFG cache by total node count across
	// all cached CFGs, preventing a single giant function from dominating
	// memory. 0 = default 400000; negative = unbounded.
	//	[scan]
	//	cfg_cache_max_total_nodes = 50000
	CFGCacheMaxTotalNodes int `toml:"cfg_cache_max_total_nodes"`
	// MaxCachedTrees bounds the parser's AST cache by tree count. 0 = default
	// 4000; a negative value keeps the legacy unbounded mode. Only trees with
	// no outstanding borrow are evicted.
	//	[scan]
	//	max_cached_trees = 2000
	MaxCachedTrees int `toml:"max_cached_trees"`
	// MemoryPressureEnabled toggles cgroup/RSS-driven backpressure scheduling.
	// When true, the pipeline monitors process memory and reduces concurrency
	// to 1 when usage exceeds MemoryHighWatermarkMB, restoring when it drops
	// below MemoryLowWatermarkMB. Default false (no backpressure).
	//	[scan]
	//	memory_pressure_enabled = true
	MemoryPressureEnabled bool `toml:"memory_pressure_enabled"`
	// MemoryHighWatermarkMB is the RSS/cgroup threshold (in MB) above which
	// the pipeline enters backpressure (stops admitting new concurrent tasks).
	//	[scan]
	//	memory_high_watermark_mb = 28000
	MemoryHighWatermarkMB int `toml:"memory_high_watermark_mb"`
	// MemoryLowWatermarkMB is the threshold below which backpressure is lifted.
	// 0 is normalized to 75% of the high watermark (a zero low would never be
	// reached and would hang every waiting task).
	//	[scan]
	// memory_low_watermark_mb = 20000
	MemoryLowWatermarkMB int `toml:"memory_low_watermark_mb"`
	// GoMemLimitMB sets the Go runtime soft memory limit (GOMEMLIMIT) for the
	// scan process. 0 = leave the runtime default. This is the knob that caps
	// the Go heap (candidates/event maps/detector temporaries), which is often
	// the largest resident component once the AST/CFG caches are bounded.
	//	[scan]
	//	go_mem_limit_mb = 24000
	GoMemLimitMB int `toml:"go_mem_limit_mb"`
	// GoGCPercent overrides GOGC for the scan process. 0 = leave the runtime
	// default. A lower value trades CPU for a lower heap peak.
	//	[scan]
	//	go_gc_percent = 50
	GoGCPercent int `toml:"go_gc_percent"`
	// SQLiteCacheMB bounds SQLite's page cache per connection (PRAGMA
	// cache_size). 0 = leave SQLite's default. SQLite page cache and WAL both
	// count toward cgroup memory, so a large repo should set this explicitly;
	// it is NOT covered by go_mem_limit_mb.
	//	[scan]
	//	sqlite_cache_mb = 64
	SQLiteCacheMB int `toml:"sqlite_cache_mb"`
	// SQLiteMmapMB sets SQLite's mmap_size (memory-mapped I/O). 0 = leave the
	// default; positive values map that many MB per connection. mmap pages are
	// counted in the process RSS on Linux.
	//	[scan]
	//	sqlite_mmap_mb = 256
	SQLiteMmapMB int `toml:"sqlite_mmap_mb"`
	// EventBatchSize caps the detector event buffer. When the buffer reaches
	// this count, emitEvent auto-flushes in one transaction instead of waiting
	// for the phase end, keeping the write-lock duration bounded on large repos.
	// 0 = default 2000; negative = phase-end-only flush (legacy behavior).
	//	[scan]
	//	event_batch_size = 2000
	EventBatchSize int `toml:"event_batch_size"`
}

// GraphBuildersConcurrencyOr returns the configured graph-builder parallelism,
// defaulting to 7 when unset (≤0 or >64 sanity-clamped).
func (c *Config) GraphBuildersConcurrencyOr(def int) int {
	n := c.Scan.GraphBuildersConcurrency
	if n <= 0 {
		n = def
	}
	if n > 64 {
		n = 64
	}
	return n
}

// PlanConcurrencyOr returns the configured plan-stage parallelism, defaulting
// to the given value when unset (≤0 or >64 sanity-clamped).
func (c *Config) PlanConcurrencyOr(def int) int {
	n := c.Scan.PlanConcurrency
	if n <= 0 {
		n = def
	}
	if n > 64 {
		n = 64
	}
	return n
}

// DetectorConcurrencyOr returns the configured detector-stage parallelism,
// defaulting to the given value when unset (≤0 or >64 sanity-clamped).
func (c *Config) DetectorConcurrencyOr(def int) int {
	n := c.Scan.DetectorConcurrency
	if n <= 0 {
		n = def
	}
	if n > 64 {
		n = 64
	}
	return n
}

// skipDetectorsOverride is the one-shot CLI override
// (`secguard scan --skip-detectors unchecked_return,memory_leak`). A non-nil
// slice replaces the config value entirely; nil leaves the file in charge.
var skipDetectorsOverride []string

// SetSkipDetectorsOverride records the --skip-detectors CLI flag. An empty
// string clears the override.
func SetSkipDetectorsOverride(csv string) {
	skipDetectorsOverride = nil
	for _, part := range strings.Split(csv, ",") {
		if n := strings.TrimSpace(part); n != "" {
			skipDetectorsOverride = append(skipDetectorsOverride, n)
		}
	}
}

// SkipDetectorNames returns the detector-skip names actually in effect: the CLI
// flag when supplied, else the [scan] skip_detectors config, trimmed and
// de-duplicated in declaration order. Unknown names are the caller's to warn
// about — config cannot know the detector registry.
func (c *Config) SkipDetectorNames() []string {
	names := c.Scan.SkipDetectors
	if skipDetectorsOverride != nil {
		names = skipDetectorsOverride
	}
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if t := strings.TrimSpace(n); t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// SkipDetectorSet returns SkipDetectorNames as a set, for O(1) lookups in the
// detector runner. A nil/empty set means "nothing skipped".
func (c *Config) SkipDetectorSet() map[string]bool {
	names := c.SkipDetectorNames()
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
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

// BoundaryAutoDismissMode normalizes the configured mode. The default is
// "external" (pre-dismiss the fail-open ASSUMPTION tiers); "off" is an explicit
// recall-maximal opt-out, and "all" is the aggressive opt-in.
func (c *Config) BoundaryAutoDismissMode() string {
	if boundaryAutoDismissOverride != "" {
		return boundaryAutoDismissOverride
	}
	if c == nil {
		return "external"
	}
	switch strings.ToLower(strings.TrimSpace(c.Scan.BoundaryAutoDismiss)) {
	case "external", "":
		return "external"
	case "all":
		return "all"
	case "off":
		return "off"
	default:
		return "external"
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

// Uninit declares project-specific uninitialized-read facts. InitializationMacros
// lists function-like macros that initialize caller locals implicitly (the
// command-message idiom: `CMD_MSG_INIT(recv)` whose body assigns execId/paraNum).
// A macro whose definition is in the scan tree is recognized from its body; a
// declaration here is the contract for a macro defined in an excluded/out-of-tree
// header, where the body is invisible: the call initializes the locals declared
// before it.
//
//	[uninit]
//	initialization_macros = ["CMD_MSG_INIT", "MSG_CTX_INIT"]
type Uninit struct {
	InitializationMacros []string `toml:"initialization_macros"`
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
	applyScanDefaults(cfg)
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
	applyScanDefaults(cfg)
	return cfg, nil
}

// applyScanDefaults bounds the per-scan caches unless the user explicitly
// opted out with a negative value. The parser/CFG/event buffers were unbounded
// by default before the lifecycle fix, which is the OOM configuration this
// change exists to remove; a negative value keeps the legacy unbounded mode for
// a deployment that has measured its own headroom.
func applyScanDefaults(c *Config) {
	if c.Scan.MaxCachedTrees == 0 {
		c.Scan.MaxCachedTrees = 4000
	}
	if c.Scan.CFGCacheMaxEntries == 0 {
		c.Scan.CFGCacheMaxEntries = 4000
	}
	if c.Scan.CFGCacheMaxTotalNodes == 0 {
		c.Scan.CFGCacheMaxTotalNodes = 400000
	}
	if c.Scan.EventBatchSize == 0 {
		c.Scan.EventBatchSize = 2000
	}
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

// UninitInitializationMacros returns the project-declared initialization macros
// (secguard.toml [uninit] initialization_macros). They are registered into
// internal/macros at CLI startup so the uninit detector and planner treat their
// body assignments as initialization even when the definition is outside the
// scan tree.
func (c *Config) UninitInitializationMacros() []string {
	if c == nil {
		return nil
	}
	return c.Uninit.InitializationMacros
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
