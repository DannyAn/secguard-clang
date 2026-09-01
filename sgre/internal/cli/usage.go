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
  --exclude <dirs>  Comma-separated directory basenames to skip`+commonFlagsDoc+`

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
  --scan-id <id>       Scan ID to query (default: latest)
  --db <path>          Path to sgre.db
  --help, -h           Show this usage

Examples:
  secguard status
  secguard status --per-type
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
  --write-json <file>      Persist findings from a JSON array file
  --scan-id <id>           Scan ID to attach findings to
  --audit                  Regenerate report.md + result.sarif + result.xlsx + findings/ from DB
  --output-dir <dir>       Output directory for audit artifacts
  --review                 Review a single finding by id
  --id <n>                 Finding id to review
  --review-status <s>      Review verdict: confirmed | dismissed | suspected-kept
  --review-reasoning <r>   One-line review justification
  --db <path>              Path to sgre.db
  --help, -h               Show this usage

Examples:
  secguard report
  secguard report --write-json /tmp/buffer-overflow.json --scan-id sc_2026-08-23_130813_395bcb
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
  it. It exists today for two options: the trusted-macro allowlist and the
  iterator-macro declaration.

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
# POOL_FOR = [1]`)
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
	"db":     printDbUsage,
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
