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
4. If no second token is present, default to **full scan mode** (all types).
5. For backward compatibility, `--type <value>`, `--types=<value>`, etc. are also accepted — if any token starts with `--type`, extract the value from the next token or after `=` and use it as the type filter instead of the positional second token.

## Valid Vulnerability Types

The authoritative type list comes from `secguard types` (JSON with `name` + `cwe`
fields). **Call `secguard types` to discover the current list — do not hardcode
the names or count**, because new types are added over time. The keyword `all` is
also accepted and is equivalent to no filter (full scan mode).

## Validation

Before proceeding, validate the type filter:
- If the filter is absent or `all` → full scan mode. Skip type validation.
- Otherwise, split the filter by comma, trim whitespace from each segment, drop empty segments, and deduplicate.
- Each remaining segment must exactly match a `name` from `secguard types` (case-sensitive, kebab-case).
- If ANY segment is invalid, STOP immediately and emit this error, listing the current valid types from `secguard types`:
  "Invalid vulnerability type '<invalid_type>'. Valid types: <comma-separated list from `secguard types`>. Example: /secguard src/ buffer-overflow"
  Do NOT proceed with any scan or tool call.

## Mode Selection

- **Full scan mode** (no filter or `all`): Follow the Full Scan Workflow below.
- **Filtered mode** (one or more specific types): Follow the Filtered Workflow below.

## Classification Rules

- Safe functions (`memcpy_s`, `strcpy_s`, `execve`, `sqlite3_prepare_v2`) → false-positive
- Safe wrappers (`SafeCopy`, `SafeQuery`, `ResourceHandle`, `LockGuard`) → false-positive
- RAII patterns (create+destroy pairs) → false-positive for leak
- Bounds check before an unsafe call → false-positive for buffer-overflow
- Partial validation (blacklist only, TOCTOU window) → suspected
- No guard + reachable + nullable source + data flow to deref → confirmed
- Only persist findings for pipeline-supported types (those returned by `secguard types`). Other issues go in the **observations table**, do NOT call `secguard_report` for them.

## Full Scan Workflow

Target path: <parsed path>

Instructions:
1. Run a full security scan on the target path using `secguard_scan`. The tool returns a summary (scan_id, output_dir, total_candidates, candidates_by_type) — NOT the full candidate list. Results are written to `.codeagent/secguard-clang/scans/<scan_id>/` (SARIF 2.1 + report.md + per-finding Markdown). The database is stored at `.codeagent/secguard-clang/.sgre/sgre.db`.
2. Read `report.md` from the output directory — it lists every candidate in a compact table grouped by vulnerability type. This is your primary classification input.
3. **Process types one at a time** (per-type batch loop) to avoid context exhaustion:
   a. For each vulnerability type with candidates > 0, load ONLY the skill for that type.
   b. Reason over each candidate of that type — classify as confirmed, suspected, or false-positive.
   c. Cross-reference evidence with source code when needed — read at most 5 source files per type batch, only at the reported file:line. Do NOT read all source files up front.
   d. Write findings for THIS type only using `secguard_report` (incremental — one type at a time, not all types in one call). Pass `scan_id` and `output_dir` from the scan output. Include dismissed (false-positive) findings with a one-line evidence explaining why they are safe.
4. **Second-round confirmation (A5)**: For every finding written with `status="suspected"`, re-read the source at its `file:line` and record a verdict via `secguard_report` `reviews` (using the `id` returned by the write): `confirmed` (promote), `dismissed` (drop), or `suspected-kept` (genuinely uncertain). Only the post-A5 verdicts count in the final summary.
5. After all type batches and the A5 pass are processed, present the result as a formal Markdown report: (a) report header `代码仓：<repo abs path>；扫描目录：<scanned dir abs path>`; (b) one-line summary `本次审计确认 X 个问题、疑似 Y 个问题。`; (c) **per-skill overview table** `| Skill | 类别 | 确认 | 疑似 | 已排除误报 |`; (d) **findings table** `| Skill | 文件:行号 | 函数 | 严重度 | 结论 | 说明 |`; (e) **observations table** `| Skill | 说明 |` only if some types are not persisted. Do NOT include pipeline internals (seed/final/deduped counts, cap, recall, benchmark, TP/FP, rule_id whitelist, scan_id) in the report. Reference the SARIF file path for machine-readable output.

## Filtered Workflow

Target path: <parsed path>
Selected types: <parsed type filter>

Instructions:
1. Review the index status from the inline status check at the top of this prompt. If `"indexed": true` and the index is fresh, proceed to step 2. If the inline check is unavailable or shows no index, call `secguard_status` to verify. If no index exists or the index is stale, call `secguard_scan` to build/refresh the index. Note the `scan_id` and `output_dir` from this call — they are needed for `secguard_report` later.
2. **Per-type batch loop**: For each SELECTED vulnerability type only:
   a. Call `secguard_plan` with `vuln_type=<type>`. If the call fails, record the failure and continue with the remaining selected types.
   b. Load ONLY the skill for this type.
   c. Reason over each candidate — classify as confirmed, suspected, or false-positive.
   d. Cross-reference evidence with source code when needed — read at most 5 source files per type, only at the reported file:line.
   e. Write findings for THIS type only using `secguard_report` (incremental). Pass `scan_id` and `output_dir` from step 1.
3. **Second-round confirmation (A5)**: For every finding written with `status="suspected"`, re-read the source at its `file:line` and record a verdict via `secguard_report` `reviews` (using the `id` returned by the write): `confirmed` (promote), `dismissed` (drop), or `suspected-kept` (genuinely uncertain). Only the post-A5 verdicts count in the final summary.
4. Present the result as a formal Markdown report for the SELECTED type(s) only: report header (`代码仓` + `扫描目录`), one-line summary, **per-skill overview table** `| Skill | 类别 | 确认 | 疑似 | 已排除误报 |`, and **findings table** `| Skill | 文件:行号 | 函数 | 严重度 | 结论 | 说明 |`. State which skills were executed and which were skipped. If any selected types failed during step 2, note them. Do NOT include pipeline internals (seed/final/deduped counts, cap, recall, benchmark, TP/FP, rule_id whitelist, scan_id) in the report. Reference the SARIF file path for machine-readable output.

## Usage Examples

- Full scan: `/secguard src/`
- Full scan (explicit): `/secguard src/ all`
- Single type: `/secguard src/ buffer-overflow`
- Multiple types: `/secguard src/ double-free,format-string`
- Multiple types (with spaces): `/secguard src/ buffer-overflow, null-deref`
