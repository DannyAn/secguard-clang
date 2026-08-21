Scan the codebase for security vulnerabilities using the SecGuard analysis pipeline.

## Tool Names & Skill Namespace (READ THIS FIRST — these two get confused constantly)

**Tool names.** You run SecGuard through the OpenCode tools, whose names carry an
underscore: `secguard_scan`, `secguard_plan`, `secguard_report`, `secguard_types`,
`secguard_status`, `secguard_index`, `secguard_schema`, `secguard_db`. These are
TOOLS, not shell commands. Do not type them as bash commands — `secguard_scan ./src`
in a shell fails with "command not found". (The CLI binary is only used by those
tools internally; you never need to run it yourself. If you ever must, it is
`secguard scan` with a space — but prefer the tools.)

**Skill names.** Only load skills whose name is EXACTLY a `name` from
`secguard types` (kebab-case, no prefix, no namespace): `buffer-overflow`,
`null-deref`, `crypto-misuse`, etc. The environment may expose other extensions'
skills with prefixed names such as `crs-buffer-overflow`, `crs-crypto-misuse`.
**Never load a prefixed skill** — those belong to another product and do not know
SecGuard's evidence schema. If the only skill you can find is prefixed, STOP and
report it rather than loading the wrong skill. The SecGuard skills live under the
`secguard-clang` extension/namespace only.

## Argument Parsing

Raw arguments: $ARGUMENTS

1. Split $ARGUMENTS by whitespace into tokens.
2. First token = **target path**. If none, use the current workspace root.
3. Second token (if present) = **type filter**: a single type (`buffer-overflow`),
   a comma list (`double-free,format-string`), or the keyword `all`.
4. No second token → full scan mode.
5. `--type <v>`, `--types=<v>` forms are also accepted.

## Valid Vulnerability Types

Call `secguard types` to discover the authoritative list (`name` + `cwe`) — never
hardcode names or counts.

## Validation

- No filter or `all` → full scan mode, skip validation.
- Otherwise split on comma, trim, dedupe; every segment must exactly equal a
  `name` from `secguard types`. Any mismatch → STOP and emit:
  "Invalid vulnerability type '<x>'. Valid types: <list>. Example: /secguard src/ buffer-overflow"

## Mode Selection

- Full scan (no filter / `all`): Full Scan Workflow.
- Filtered (specific types): Filtered Workflow.

## Classification Rules

- **Safe functions** (`memcpy_s`, `strcpy_s`, `execve`, `sqlite3_prepare_v2`) are
  normally *false-positive* — a real guard that eliminates the risk. But that is
  the DEFAULT, not a blank cheque: if the call site breaks the safety contract
  (dest size still overflows, size argument lies, return value unchecked when it
  must be), classify **confirmed**. "The function is safe" is not the same as
  "this call is safe".
- **Weak crypto is confirmed, period.** CWE-327 is defined by the algorithm, not
  by intent: DES, 3DES, MD5, SHA-1, RC4, `rand()` are weak. Do NOT excuse them as
  "legacy compatibility" or "maybe by design" — those are **confirmed**, with a
  fix_strategy pointing at AES-256 / SHA-256 / a CSPRNG. "Borderline" is not a
  verdict.
- Safe wrappers (SafeCopy, SafeQuery, ResourceHandle, LockGuard) → false-positive.
- RAII (create+destroy pairs) → false-positive for leak.
- Bounds check before an unsafe call → false-positive for buffer-overflow.
- Partial validation (blacklist only, TOCTOU window) → suspected.
- No guard + reachable + nullable source + data flow to deref → confirmed.
- Persist ONLY pipeline-supported types (from `secguard types`); anything else
  goes in the observations table, never through `secguard_report`.

## Source-Path Handling (avoids wasting turns)

`report.md` shows paths relative to the scan target; the `## Location` block of
each `candidates/<vuln-type>/NNN_*.md` file carries the **absolute** path. Before
reading source, take the absolute path from the candidate file's Location block
(or the `files_with_candidates` list in the scan summary) and use it directly.
Do not reconstruct paths by trial and error.

## Full Scan Workflow

Target path: <parsed path>

**The single most important rule of this whole workflow: findings do not exist
until you call `secguard_report`, and `findings/` + `result.sarif` do not exist
until the write carries `scan_id` + `output_dir`. You MUST write each type's
findings before moving to the next type. "Analyze all types first, write at the
end" is WRONG and loses work.** Track processed types in your todo list so no
type is skipped or double-processed.

1. **Scan**: call the `secguard_scan` tool with the target path. It returns a
   summary (`scan_id`, `output_dir`, `candidates_by_type`, `total_candidates`).
   Record `scan_id` and `output_dir` — you will need both in every write. If the
   summary has `report_error`, stop and surface it.
2. **Read `report.md`** from `output_dir`: the compact per-type candidate tables.
3. **Per-type batch loop** (for each type with candidates > 0, in report.md order):
   a. Load ONLY that type's skill (exact kebab-case name, SecGuard namespace).
   b. Classify every candidate: confirmed / suspected / false-positive.
   c. Cross-reference source: ≤5 files, only at file:line, using absolute paths.
   d. **WRITE now**: call `secguard_report` with `findings` for THIS type only,
      passing BOTH `scan_id` and `output_dir`. Every candidate gets a finding —
      confirmed, suspected, or dismissed. Never dismiss a batch "in prose only":
      each dismissal must be a `secguard_report` entry with `reasoning`. For
      confirmed, always fill `reasoning` + `exception_check` + `fix_strategy`.
      If the response has `per_finding_warning` or the `written` array is short,
      fix the call and re-write. **Do not proceed to the next type until the
      write succeeds.**
   e. A5 (second round): for each `suspected` you just wrote, record a verdict via
      `secguard_report` `reviews` (`confirmed`/`dismissed`/`suspected-kept` +
      `review_reasoning`), using the `id`s from the write response.
4. **Finalize and verify the artifacts** (after all types): `result.sarif` and
   `findings/` are regenerated automatically by every `secguard_report` write
   that carries `scan_id` + `output_dir`. So after the loop, read
   `<output_dir>/result.sarif` (must be non-empty) and list
   `<output_dir>/findings/`. If `result.sarif` is missing/empty, or `findings/`
   has no `_confirmed`/`_suspected` files even though you wrote findings — a
   write did not land; find the `per_finding_warning`, fix it, and re-write.
   **A final report without a verified `result.sarif` and `findings/` is
   incomplete.**
5. **Report**: emit the Markdown report (报告头 / 摘要 / 总览表 / 问题表 /
   观察项表 / 修复建议 / 逐条详情) per the Output Format. Reference
   `result.sarif` and `findings/` only after step 4 verified them.

## Filtered Workflow

Target path: <parsed path>
Selected types: <parsed type filter>

1. Check index status (inline status at top of prompt, or `secguard_status`).
   If absent/stale, call `secguard_scan` to build it; record `scan_id` +
   `output_dir` from that call.
2. **Per-type batch loop** for each SELECTED type:
   a. `secguard_plan` with `vuln_type=<type>`. On failure, record and continue.
   b. Load ONLY that type's skill (exact name, SecGuard namespace).
   c. Classify every candidate.
   d. Cross-reference: ≤5 files, absolute paths from the candidate Location block.
   e. **WRITE now**: `secguard_report` with `findings` for THIS type, passing
      `scan_id` + `output_dir`. Every candidate gets a verdict; confirmed findings
      carry `reasoning` + `exception_check` + `fix_strategy`. Handle
      `per_finding_warning` before moving on.
   f. A5: `secguard_report` `reviews` for every `suspected`.
3. **Finalize and verify**: after the loop, read `<output_dir>/result.sarif`
   (non-empty) and list `<output_dir>/findings/` to confirm your verdicts
   landed; if not, fix the failing write before reporting.
4. Report for the selected types only (报告头 / 摘要 / 总览表 / 问题表), note
   skipped/failed types, reference `result.sarif` only after verifying it.

## Output Format (final reply to the user)

Report the diagnostic conclusion in Chinese, Markdown tables only:

1. 报告头: `代码仓：<repo abs path>；扫描目录：<scanned dir abs path>`
2. 摘要: `本次审计确认 X 个问题、疑似 Y 个问题。` (X/Y = confirmed/suspected verdicts, NOT candidate counts)
3. 总览表: `| Skill | 类别 | 确认 | 疑似 | 已排除误报 |`
4. 问题表: `| Skill | 文件:行号 | 函数 | 严重度 | 结论 | 说明 |` (confirmed + suspected)
5. 观察项表 (only if some types were not persisted): `| Skill | 说明 |`
6. 修复建议: per-confirmed paste-ready fix (a `c` code block each)
7. 逐条详情: Reasoning / Exception Check / Fix Strategy per confirmed+suspected

Never include pipeline internals (seed/final/deduped counts, cap, recall,
benchmark, TP/FP, rule_id, whitelist, scan_id, timestamps) in the reply.

## Usage Examples

- Full scan: `/secguard src/`
- Full scan (explicit): `/secguard src/ all`
- Single type: `/secguard src/ buffer-overflow`
- Multiple types: `/secguard src/ double-free,format-string`
- Multiple types (with spaces): `/secguard src/ buffer-overflow, null-deref`
