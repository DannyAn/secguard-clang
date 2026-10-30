package cli

import (
	"fmt"
	"os"
	"strings"
)

// hasHelpFlag reports whether args contain --help or -h. It is the per-subcommand
// gate inserted before every runXxxCmd dispatch so `secguard <cmd> --help` prints
// usage instead of falling through into the command's default logic.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}

// commonFlagsDoc is the shared flag block appended to every subcommand usage.
const commonFlagsDoc = `
Common Flags:
  --db <path>          Path to sgre.db (default: .codeagent/secguard-clang/.sgre/sgre.db)
  --context-lines <n>  Source lines embedded on each side of a finding (default 15, 0 disables)
  --help, -h           Show this usage`

func printIndexUsage() {
	fmt.Fprintln(os.Stdout, `secguard index - Index a C codebase into the analysis database

Usage:
  secguard index <path>

Arguments:
  <path>   Root directory of the C codebase to index

Flags:
  --exclude <dirs>  Comma-separated directory basenames to skip
                    (default: deps,third_party,vendor,external,node_modules,tests,test,fuzzing,contrib,examples)`+commonFlagsDoc+`

Example:
  secguard index ./src`)
}

func printScanUsage() {
	fmt.Fprintln(os.Stdout, `secguard scan - Full pipeline: index + plan all vuln types + report

Usage:
  secguard scan <path> [type-filter]

Arguments:
  <path>        Root directory of the C codebase to scan
  [type-filter] Optional: a single type, comma list, or "all" (default: all)

Flags:
  --exclude <dirs>  Comma-separated directory basenames to skip
  --fail-on <level> Exit code 2 when any finding is confirmed (only "confirmed" is supported)
  --boundary-auto-dismiss <mode>
                    Boundary scans only: pre-dismiss fail-open null-deref rows
                    (off default | external | all). "external" drops opaque/
                    external null origins; "all" also drops caller-arg/assumed-
                    return rows without an in-tree chain.`+commonFlagsDoc+`

Examples:
  secguard scan ./src
  secguard scan ./src buffer-overflow
  secguard scan ./src double-free,format-string`)
}

func printStatusUsage() {
	fmt.Fprintln(os.Stdout, `secguard status - Show index status and scan progress

Usage:
  secguard status [flags]

Flags:
  --per-type           Show per-vuln-type status (candidate/written/terminal) as JSON
  --reports            List settled subagent reports from .sgre/.tmp/*-report*.json
  --scan-id <id>       Scan ID to query (default: latest / all reports)
  --db <path>          Path to sgre.db
  --help, -h           Show this usage

Examples:
  secguard status
  secguard status --per-type
  secguard status --reports --scan-id sc_2026-08-23_130813_395bcb
  secguard status --per-type --scan-id sc_2026-08-23_130813_395bcb`)
}

func printQueryUsage() {
	fmt.Fprintln(os.Stdout, `secguard query - Run a skill query against the indexed codebase

Usage:
  secguard query <skill> [flags]

Arguments:
  <skill>   Skill name to run (e.g. buffer-overflow, null-deref)

Flags:
  --db <path>   Path to sgre.db
  --help, -h    Show this usage

Example:
  secguard query buffer-overflow`)
}

func printTypesUsage() {
	fmt.Fprintln(os.Stdout, `secguard types - List all registered vulnerability types with CWE mappings (JSON)

Usage:
  secguard types [flags]

Flags:
  --help, -h   Show this usage

Example:
  secguard types`)
}

func printClassifyUsage() {
	fmt.Fprintln(os.Stdout, `secguard classify - Deterministically classify candidates (route-B executor)

Usage:
  secguard classify <path> [flags]

Arguments:
  <path>   C target path (the pipeline re-plans it and classifies the result)

Flags:
  --mode <m>        agent (default, LLM-orchestrator path) | executor (deterministic)
  --dry-run         With --mode executor: use DismissAllRunner (no LLM) to prove the wiring
  --batch-size <n>  Candidates per worker batch (default 20)
  --db <path>       Path to sgre.db
  --help, -h        Show this usage`)
}

func printPlanUsage() {
	fmt.Fprintln(os.Stdout, `secguard plan - Run the convergence pipeline for a single vulnerability type

Usage:
  secguard plan <vuln-type> [flags]

Arguments:
  <vuln-type>   Vulnerability type name (from "secguard types")

Flags:
  --db <path>   Path to sgre.db
  --help, -h    Show this usage

Example:
  secguard plan buffer-overflow`)
}

func printReportUsage() {
	fmt.Fprintln(os.Stdout, `secguard report - Output, persist, or audit findings

Usage:
  secguard report [flags]

Flags:
  --write-json <file>      Persist findings from a JSON array file (see below)
  --scan-id <id>           Scan ID to attach findings to
  --list                   Read all findings from the DB (optional --status filter)
  --status <s>             With --list: filter by effective verdict (confirmed | dismissed)
  --audit                  Regenerate report.md + result.sarif + result.xlsx + findings/ from DB
  --output-dir <dir>       Output directory for audit artifacts
  --list-auto-confirmed    List machine (auto-confirmed) findings with no review verdict yet
                           (each entry carries reasoning, the one-line snippet, and a
                           gutter-numbered ±8-line context window around the finding)
  --type <kebab,...>       With --list-auto-confirmed: scope the list to these vuln types
  --limit <n>              With --list-auto-confirmed: cap the batch size (0 = no cap)
  --review                 Review a single finding by id
  --id <n>                 Finding id to review
  --review-status <s>      Review verdict: confirmed | dismissed
  --review-reasoning <r>   One-line review justification
  --review-json <file>     Re-review auto-confirmed findings from a JSON array (see below)
  --complete-type <type>   Mark AI stage done for a vulnerability type (sets ai_stage_status=done)
  --db <path>              Path to sgre.db
  --help, -h               Show this usage

--write-json payload: a JSON ARRAY of finding objects ("-" or omitted reads stdin):
  [{"rule_id":"CWE-476","severity":"high","confidence":90,"status":"confirmed",
    "file":"src/a.c","line":42,"function":"f","summary":"...","reasoning":"...",
    "exception_check":"...","fix_strategy":"..."}]
  rule_id is the CWE; status is confirmed (dismissed candidates are not written — skipped). A single
  finding object, or an object {"scan_id":"...","findings":[...]}, is also
  accepted. The write is idempotent (UPSERT on scan_id+rule_id+file+line+function).
  "file"/"line"/"function" are required for a confirmed finding; the DB-column
  spellings "file_path"/"line_number"/"function_name" are accepted as aliases.

--review-json payload: a JSON ARRAY of objects re-reviewing auto-confirmed findings.
  REQUIRED per object: "id" (finding id from --list-auto-confirmed) and
  "review_status" ("confirmed" | "dismissed"). "review_reasoning" is optional:
  [{"id":13,"review_status":"dismissed","review_reasoning":"getter borrow, not an allocation"}]
  A missing/misspelled required key is reported by entry position. A partial
  batch exits non-zero; re-run --audit and check for unreviewed_auto_confirmed.

Examples:
  secguard report --list
  secguard report --list --status confirmed
  secguard report --write-json /tmp/buffer-overflow.json --scan-id sc_2026-08-23_130813_395bcb
  secguard report --list-auto-confirmed --scan-id sc_2026-08-23_130813_395bcb
  secguard report --review-json /tmp/auto-confirmed-review.json
  secguard report --audit --scan-id sc_2026-08-23_130813_395bcb --output-dir ./scans/sc_x
  secguard report --review --id 1 --review-status dismissed --review-reasoning "guarded by bounds check"`)
}

func printDbUsage() {
	fmt.Fprintln(os.Stdout, `secguard db - Execute a SQL query on sgre.db and return rows as JSON

Usage:
  secguard db <sql> [flags]

Arguments:
  <sql>   SQL query string (quote shell-special characters)

Flags:
  --db <path>   Path to sgre.db
  --help, -h    Show this usage

Example:
  secguard db "SELECT rule_id, COUNT(*) FROM findings GROUP BY rule_id"`)
}

func printDefUsage() {
	fmt.Fprintln(os.Stdout, `secguard def - Resolve a symbol definition from the index (no repo-wide grep)

Usage:
  secguard def <symbol> [<symbol> ...] [flags]

Arguments:
  <symbol>   One or more C identifiers to locate (function, declaration, macro,
             type, variable); up to 16 per call

Flags:
  --kind <k>    Restrict the lookup: auto (default) | function | declaration |
                macro | type | variable
  --in <file>   Also scan this file for a #define of <symbol> (a macro local to
                the candidate's own .c); relative paths resolve against --root
  --root <dir>  Project root for the header scan (default: the indexed files'
                common root, or its nearest include/inc ancestor)
  --db <path>   Path to sgre.db
  --help, -h    Show this usage

Output (JSON):
  single: {symbol, found, external, definitions:[{kind,file,line,end_line,signature,body}]}
  batch:  {symbols, results:[...], found}

Examples:
  secguard def ase_sa_str_connect
  secguard def sa_print_ipv4_string sa_print_ipv6_string
  secguard def GET_STR_LEN
  secguard def TICKS_IN_SECOND --kind macro
  secguard def LOCAL_MACRO --in src/service/ase_sa_dfx.c`)
}

func printSchemaUsage() {
	fmt.Fprintln(os.Stdout, `secguard schema - Show the DB schema for agent-queryable tables

Usage:
  secguard schema [table] [flags]

Arguments:
  [table]   Optional table name to show a single table's schema (default: all)

Flags:
  --db <path>   Path to sgre.db
  --help, -h    Show this usage

Examples:
  secguard schema
  secguard schema findings`)
}

func printConfigUsage() {
	fmt.Fprintln(os.Stdout, `secguard config - Show the effective secguard.toml configuration

Usage:
  secguard config [flags]

Flags:
  --example       Print a full copy-paste secguard.toml example
  --help, -h      Show this usage

What it is:
  secguard.toml is an OPTIONAL configuration file. Most users need nothing in
  it. It exists for the trusted-macro allowlist, project iterator macros, the
  banned-function extension, directory exclusions, the vulnerability-type
  switch, project allocator/deallocator/ownership-transfer names, return
  nullability, framework-guaranteed pointer parameters, the scan entry-point
  boundary policy, and integer-overflow truncating wrappers.

  Config file locations, in priority order (first existing wins):
    1. --config <path>                     explicit flag
    2. SECGUARD_CONFIG env var
    3. <cwd>/.codeagent/secguard.toml      per-repository (commit it)
    4. ~/.codeagent/secguard.toml          personal default (generated on install)

  With no file present, secguard uses built-in defaults (an empty config).

  [trusted_macros] — trusted accessor macros
    names = ["..."]
    A macro whose expansion computes a pointer from a memory address
    (field + offset arithmetic) rather than a possibly-null allocation/lookup
    result. Callers dereference it without a null check by contract, so
    secguard must not report a null-deref there. Add a name here only when the
    macro's DEFINITION is outside the scan tree (e.g. an SDK header), where the
    automatic macro-pattern recognition cannot see it.

  [iterator_macros.macros] — project iterator macros
    MACRO_NAME = [index, ...]
    A function-like macro that writes its iterator parameter(s) in the for-init
    clause and null-guards them in the loop condition (so the iterator is
    provably non-null inside the loop body), whose DEFINITION is outside the
    scan tree. Each value is the 0-based index of an iterator parameter.
    Example: SAMPLE_Scan(list, iter, type) writes 'iter' (index 1):
      [iterator_macros.macros]
      SAMPLE_Scan = [1]
    Standard Linux list-traversal macros (list_for_each_entry & friends) are
    built-in and do NOT need to be declared here.

  [banned_functions] — dangerous-function policy (CWE-676)
    names   = ["..."]   # ADD project bans (category "config_banned")
    exclude = ["..."]   # REMOVE built-ins your guideline does not list
    The built-in table (process/thread exit, alloca, setjmp/longjmp, the non-_s
    mem/str/format/scan families, atoi/atol/atoll/atof, realloc, assert, and
    the obsolete/insecure APIs) is a DEFAULT policy, not your guideline's
    authoritative list: "names" extends it, "exclude" trims it (a name in both
    is excluded). It is a policy check: a call is flagged regardless of
    surrounding bounds checks, because the enterprise bans the function itself.
    Every category is auto-confirmed except assert usage (handed to the AI
    agent). The deprecated BSD trio (bzero/bcopy/bcmp) is NOT in the default
    table; add those names if your standard bans them.

  [exclude] — directory trees to skip at index time
    paths = ["..."]
    Directories to prune entirely during the file walk, resolved against the
    SCAN TARGET (the <path> argument). A relative entry like "./svc/src/bak/"
    with "secguard scan ./src" excludes ./src/svc/src/bak; with
    "secguard scan ." it excludes ./svc/src/bak. An absolute path is used
    as-is. Unlike the --exclude flag (which matches directory BASENAMES), these
    match the full path, so only that specific directory is skipped.

  [disabled_types] — vulnerability-type switch (turn a type OFF entirely)
    types = ["..."]
    Kebab-case vulnerability-type names (from 'secguard types') to disable for
    the WHOLE scan. A disabled type produces no candidates: the convergence
    plan stage never runs for it, so the AI agent's skills never receive it.
    Use this for noisy/slow types you do not want surfaced or billed for.
    Example: types = ["path-traversal", "divide-by-zero"].

  [allocators] / [deallocators] — project allocation/release names
    names = ["..."]
    Allocation (nat_malloc, VOS_MALLOC) and release (nat_free, VOS_FREE)
    wrappers whose definitions live outside the scan tree. The memory
    detectors treat their results/calls exactly like malloc/free (the result
    may be NULL and must be released).

  [ownership_transfer_calls] — project ownership-transfer names
    names = ["..."]
    Functions that take ownership of a pointer argument (list_push_back,
    dict_set), so a pointer passed to them has escaped rather than leaked.

  [nullability.non_null_returns] — never-null return names
    names = ["..."]
    Functions with an abort-on-failure contract (xmalloc, g_malloc, sdsnew)
    whose result is never NULL, so a dereference of it is not a null-deref.

  [nullability.non_null_params] — framework-guaranteed pointer parameters
    names = ["..."]
    Pointer PARAMETER names whose value an out-of-tree framework guarantees
    non-null (a data-plane callback's user_data, an IPC/CLI dispatcher's
    reply_msg or output slot). In a BOUNDARY scan (a subtree with no entry
    point) every zero-caller pointer parameter is otherwise treated as an
    external caller's argument (fail-open), the largest single source of
    null-deref candidates. This suppresses only that ASSUMPTION: a call site
    that demonstrably passes literal NULL still surfaces.

  [scan] — scan boundary policy
    entry_points = ["..."]
    Program entry points that live IN the scanned tree but are not main (a
    firmware task body, an RTOS thread entry). A tree containing one is scanned
    in COMPLETE-PROGRAM mode, which closes the boundary fail-open for
    parameters whose type layout is visible in-tree.

  [integer_overflow.truncating_wrappers] — bounded-return wrappers
    wrapper_name = <size_arg_index>
    Functions whose return value is bounded by one of their arguments (the
    capacity/size argument at the given 0-based index), so an accumulator built
    from their returns cannot exceed the buffer and a later 'size - total'
    subtraction cannot underflow.

Examples:
  secguard config
  secguard config --example`)
}

func printConfigExample() {
	fmt.Fprintln(os.Stdout, `# SecGuard configuration (optional). Uninstall/reinstall does not delete this.
# Put this at ~/.codeagent/secguard.toml (personal) or
# <repo>/.codeagent/secguard.toml (per-repository, commit it).

[trusted_macros]
names = [
    # "YOUR_ACCESSOR_MACRO",
]

# Project-specific iterator macros whose definitions are outside the scan tree
# (e.g. in an SDK header). Each value is the 0-based index of an iterator
# parameter written by the macro's for-init and null-guarded by the loop.
# Standard list_for_each_entry & friends are built-in; do NOT repeat them here.
[iterator_macros.macros]
# SAMPLE_Scan = [1]
# POOL_FOR = [1]

# Dangerous-function policy (CWE-676). The built-in table is a DEFAULT policy,
# not your guideline: "names" ADDS project bans (category "config_banned"),
# "exclude" REMOVES a built-in your own security guideline does not list (e.g.
# the deprecated BSD bzero/bcopy/bcmp trio, or a function your standard allows).
# A name in both lists is excluded.
[banned_functions]
names = [
    # "my_legacy_alloc",
]
exclude = [
    # "realloc",
]

# Directory trees to skip at index time. Each path is resolved against the SCAN
# TARGET (the <path> argument), not the working directory: with "secguard scan
# ./src", "./svc/src/bak/" excludes ./src/svc/src/bak. Absolute paths are also
# accepted. Unlike --exclude (which matches directory BASENAMES), these match
# the full path.
[exclude]
paths = [
    # "./svc/src/bak/",
    # "src/generated",
]

# Vulnerability-type switch: turn a whole type OFF. A disabled type produces no
# candidates (the plan stage never runs for it), so the AI agent's skills never
# receive it. Use it for noisy/slow types you don't want surfaced or billed for.
# Names are kebab-case, from 'secguard types'.
[disabled_types]
types = [
    # "path-traversal",
    # "divide-by-zero",
]

# Project-specific allocation / release wrappers whose definitions live outside
# the scan tree. The memory detectors treat their results/calls exactly like
# malloc/free (the result may be NULL and must be released).
[allocators]
names = [
    # "nat_malloc",
]

[deallocators]
names = [
    # "nat_free",
]

# Functions that take ownership of a pointer argument, so a pointer passed to
# them has escaped rather than leaked.
[ownership_transfer_calls]
names = [
    # "list_push_back",
]

# Functions with an abort-on-failure contract whose result is never NULL, so a
# dereference of it is not a null-deref.
[nullability.non_null_returns]
names = [
    # "xmalloc",
]

# Functions whose return value is bounded by one of their arguments (the
# capacity/size argument at the given 0-based index), so an accumulator built
# from their returns cannot exceed the buffer and a later 'size - total'
# subtraction cannot underflow.
[integer_overflow.truncating_wrappers]
# nlog_syslog_add_pri = 1

# Pointer PARAMETER names that an out-of-tree framework guarantees non-null
# (a data-plane callback's user_data, an IPC/CLI dispatcher's reply_msg or
# output slot). In a BOUNDARY scan (a subtree with no entry point) every
# zero-caller pointer parameter is otherwise treated as an external caller's
# argument (fail-open) — the largest single source of null-deref candidates.
# This suppresses only that ASSUMPTION: a call site that demonstrably passes
# literal NULL still surfaces (evidence beats the declaration).
[nullability.non_null_params]
names = [
    # "user_data",
    # "reply_msg",
    # "out_msg",
]

# Program entry points that live IN the scanned tree but are not main (a
# firmware task body, an RTOS thread entry). A tree containing one is scanned in
# COMPLETE-PROGRAM mode, which closes the boundary fail-open for parameters whose
# type layout is visible in-tree.
[scan]
entry_points = [
    # "thread_entry",
]
# Boundary scan (no entry point in the tree) fail-open null-deref pre-dismissal:
# "off" (default) keeps every candidate for AI judgment; "external" drops
# opaque/external null origins; "all" also drops caller-arg/assumed-return rows
# with no in-tree chain. Every dropped row is counted as boundary_fail_open.
# boundary_auto_dismiss = "external"`)
}

// subcommandUsage maps a subcommand name to its usage printer. Execute uses this
// to dispatch `secguard <cmd> --help` without falling through into the command.
var subcommandUsage = map[string]func(){
	"index":  printIndexUsage,
	"scan":   printScanUsage,
	"status": printStatusUsage,
	"query":  printQueryUsage,
	"types":  printTypesUsage,
	"plan":   printPlanUsage,
	"report": printReportUsage,
	"classify": printClassifyUsage,
	"db":     printDbUsage,
	"def":    printDefUsage,
	"symbol": printDefUsage,
	"schema": printSchemaUsage,
	"config": printConfigUsage,
}

// dispatchHelp returns true if args[0] is a known subcommand and args[1:] contain
// --help/-h, printing that subcommand's usage. It returns false (no action) when
// there is no help flag or the subcommand is unknown, so the caller proceeds with
// normal dispatch.
func dispatchHelp(args []string) bool {
	if len(args) == 0 {
		return false
	}
	printer, ok := subcommandUsage[args[0]]
	if !ok {
		return false
	}
	if !hasHelpFlag(args[1:]) {
		return false
	}
	printer()
	return true
}

// ensure strings import is used even if future edits drop direct usage.
var _ = strings.HasPrefix
