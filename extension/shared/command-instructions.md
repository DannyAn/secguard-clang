Scan the codebase for security vulnerabilities using the SecGuard analysis pipeline.

## Argument Parsing

Raw arguments: $ARGUMENTS

Parse the arguments as follows:
1. Split $ARGUMENTS by whitespace into tokens.
2. The first token is the **target path**. If no tokens remain, use the current workspace root as the target path.
3. The second token (if present) is the **type filter**. This can be:
   - A single vulnerability type: `buffer-overflow`
   - A comma-separated list of types: `double-free,format-string`
   - The keyword `all` (equivalent to no filter — full scan mode)
4. If no second token is present, default to **full scan mode** (all 15 types).
5. For backward compatibility, `--type <value>`, `--types=<value>`, etc. are also accepted — if any token starts with `--type`, extract the value from the next token or after `=` and use it as the type filter instead of the positional second token.

## Valid Vulnerability Types (15)

null-deref, buffer-overflow, memory-leak, injection, resource-leak, uninit,
use-after-free, double-free, format-string, integer-overflow, race-condition,
hardcoded-secret, deadlock, crypto-misuse, out-of-bounds

The keyword `all` is also accepted as the type filter value and is equivalent to no filter (full scan mode).

## Validation

Before proceeding, validate the type filter:
- If the filter is absent or `all` → full scan mode. Skip type validation.
- Otherwise, split the filter by comma, trim whitespace from each segment, drop empty segments, and deduplicate.
- Each remaining segment must exactly match one of the 15 valid types above (case-sensitive, kebab-case).
- If ANY segment is invalid, STOP immediately and emit this error:
  "Invalid vulnerability type '<invalid_type>'. Valid types: null-deref, buffer-overflow, memory-leak, injection, resource-leak, uninit, use-after-free, double-free, format-string, integer-overflow, race-condition, hardcoded-secret, deadlock, crypto-misuse, out-of-bounds. Example: /secguard src/ buffer-overflow"
  Do NOT proceed with any scan or tool call.

## Mode Selection

- **Full scan mode** (no filter or `all`): Follow the Full Scan Workflow below.
- **Filtered mode** (one or more specific types): Follow the Filtered Workflow below.

## Full Scan Workflow

Target path: <parsed path>

Instructions:
1. Run a full security scan on the target path using `secguard_scan`. Results are written to `.codeagent/zhuque-secguard/scans/<scan_id>/` (SARIF 2.1 + report.md + per-finding Markdown). The database is stored at `.codeagent/zhuque-secguard/.sgre/sgre.db`.
2. Read `report.md` from the output directory for the human-readable summary.
3. For each vulnerability type present in the results, load the corresponding skill for classification guidance.
4. Reason over each evidence package — classify as confirmed, suspected, or false-positive.
5. Cross-reference evidence with source code when needed (read per-finding Markdown files in `<vuln-type>/` subdirectories for detailed evidence).
6. Write confirmed and suspected findings to the SecGuard database using `secguard_report`. Pass `scan_id` and `output_dir` from the scan output.
7. Present a summary table of all findings with severity, confidence, location, and suggested fixes. Reference the SARIF file path for machine-readable output.

## Filtered Workflow

Target path: <parsed path>
Selected types: <parsed type filter>

Instructions:
1. Review the index status from the inline status check at the top of this prompt. If `"indexed": true` and the index is fresh, proceed to step 2. If the inline check is unavailable or shows no index, call `secguard_status` to verify. If no index exists or the index is stale, call `secguard_scan` to build/refresh the index. Note the `scan_id` and `output_dir` from this call — they are needed for `secguard_report` later. The evidence packages from this scan are NOT used for classification; only the index is needed.
2. For each selected vulnerability type, call `secguard_plan` with `vuln_type=<type>`. Collect evidence packages from all calls. If a `secguard_plan` call fails, record the failure and continue with the remaining types.
3. Read per-finding Markdown files from the `<vuln-type>/` subdirectories for each type that returned results.
4. Load ONLY the skill(s) for the selected type(s). Do NOT load skills for unselected types.
5. Reason over each evidence package — classify as confirmed, suspected, or false-positive.
6. Cross-reference evidence with source code when needed (read per-finding Markdown files in `<vuln-type>/` subdirectories for detailed evidence).
7. Write confirmed and suspected findings using `secguard_report`. Pass `scan_id` and `output_dir` from step 1 (or from the most recent `secguard_scan` call) so findings are associated with the scan.
8. Present a summary table for the selected type(s) only with severity, confidence, location, and suggested fixes. If any types failed during step 2, note them in the report. Reference the SARIF file path for machine-readable output.

## Usage Examples

- Full scan: `/secguard src/`
- Full scan (explicit): `/secguard src/ all`
- Single type: `/secguard src/ buffer-overflow`
- Multiple types: `/secguard src/ double-free,format-string`
- Multiple types (with spaces): `/secguard src/ buffer-overflow, null-deref`
