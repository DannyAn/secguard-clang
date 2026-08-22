Scan the codebase for security vulnerabilities using the SecGuard analysis pipeline.

## Tool Names & Skill Namespace (READ THIS FIRST — these two get confused constantly)

**Which platform am I on?** Two invocation styles exist, and they do NOT mix:

- **OpenCode** — you have MCP tools with underscore names: `secguard_scan`,
  `secguard_plan`, `secguard_report`, `secguard_types`, `secguard_status`,
  `secguard_index`, `secguard_schema`, `secguard_db`. Use those TOOLS, never
  shell commands.
- **Claude Code (and any shell-only host)** — there are NO `secguard_*` tools.
  Run the `secguard` binary via Bash with a space: `secguard scan`, `secguard
  plan`, `secguard report`, `secguard types`, `secguard status`. This doc uses
  the OpenCode tool names below; translate them to `secguard <verb>` on Claude
  Code.

**Writing findings (the part that differs most by platform).** NEVER generate a
per-finding Bash loop script — it is slow and error-prone. There is a batch mode
that writes a whole type's findings in ONE command, idempotently (re-running
updates, never duplicates):

```bash
secguard report --write-json <tmpdir>/<type>.json --scan-id <scan_id> --db <db_path>
```

`<tmpdir>` is `<project>/.codeagent/secguard-clang/.sgre/.tmp/` — the project's
own runtime temp dir, NOT `/tmp`. The scan step creates it and clears it at the
start of each run, so you can write one JSON file per type there and never worry
about cleanup (stale files from a previous run are removed by the next scan).
This path is the same on Windows and macOS/Linux.

`<type>.json` is a JSON ARRAY of finding objects with exactly these keys
(`severity` and `status` are lowercased by the CLI; `confidence` is 0–100):

```json
[
  {"rule_id":"CWE-476","severity":"high","confidence":90,"status":"confirmed",
   "file":"src/a.c","line":42,"function":"f","summary":"...",
   "reasoning":"...","exception_check":"...","fix_strategy":"..."}
]
```

Escaping: every `"` INSIDE a string value must be escaped as `\"`, and any
backslash as `\\`. Do NOT hand-write JSON with unescaped inner quotes — the CLI
will reject it. Prefer writing the JSON file with the Write tool (it does not
escape for you — escape the quotes yourself), then call `--write-json <path>`.

Write one `--write-json` per type (all of that type's findings in one array),
then run `secguard report --audit --scan-id <scan_id> --output-dir <scan_dir>`
ONCE at the very end to regenerate `result.sarif` + `findings/`. On OpenCode the
`secguard_report` tool already does this loop + audit for you (and JSON-encodes
for you).

**Never** re-run a write to "verify" it — the write is idempotent, and `secguard
db` is read-only, so a stray duplicate would force you to edit SQLite by hand.
Verify with `secguard report --audit` (read back findings), not by re-writing.

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
until the write carries `scan_id` + `output_dir`. Every type's findings must be
written the moment it is classified — by the subagent (parallel) or by you (the
fallback loop) — never accumulate all writes to the end. "Analyze all types
first, write at the end" is WRONG and loses work.** Track processed types in
your todo list so no type is skipped or double-processed.

**Context budget (the other thing that makes this fast).** Do NOT read all
source files up front — read at most 5 files per type, only at the reported
file:line, and only for candidates that actually need verification. The same
≤5-files budget covers the A5 second round (A5 normally re-judges from context +
persisted reasoning; it opens source only for a suspected finding whose file was
not already read). Do NOT load a skill for a type that has 0 candidates.
`report.md` is your primary candidate input (one compact read); the scan summary
already gives you the per-type counts.

1. **Scan**: call the `secguard_scan` tool with the target path. It returns a
   summary (`scan_id`, `output_dir`, `candidates_by_type`, `total_candidates`).
   Record `scan_id` and `output_dir` — you will need both in every write. If the
   summary has `report_error`, stop and surface it. `secguard_scan` already ran
   the convergence for EVERY type and wrote `report.md` + `candidates/` — do NOT
   re-run `secguard_plan` or `secguard_index` afterward.
2. **Scale gate — pick ONE path and stay on it.** Parallelism is NOT free: every
   subagent re-pays a fresh prompt + skill reloads + report.md re-read, so it is
   a NET LOSS on small codebases. Decide by `total_candidates` from the scan
   summary:
   - **`total_candidates ≤ 200` → SEQUENTIAL (step 3).** Classify everything
     yourself in one context. This is faster and cheaper — one context amortizes
     the skill loads and the single report.md read. Do NOT spawn subagents.
   - **`total_candidates > 200` (or `report.md` > ~40 KB) → PARALLEL (step 4).**
     Only now does a single context risk exhaustion; dispatch subagents.
3. **Sequential loop** (the normal path for small scans): for each type with
   candidates > 0, in report.md order — load that type's skill, classify every
   candidate (confirmed/suspected/dismissed), write findings in ONE batch: write `<tmpdir>/<type>.json` with the Write tool,
   then `secguard report --write-json <tmpdir>/<type>.json --scan-id <scan_id> --db <db_path>`.
   Then A5-review suspected findings, move on. Never skip a type. Obey
   the context budget (≤5 files/type, no full-tree source reads, no skill for a
   0-candidate type).
4. **Parallel dispatch** (ONLY when step 2 says so): spawn one subagent PER BATCH
   of types that have candidates > 0, ALL IN THE SAME TURN so they run
   concurrently:
   - Claude Code: the `Task` tool with `subagent_type: "security-auditor"`.
   - OpenCode: the `task` tool with the `security-auditor` agent (same name).
   Each subagent prompt must be self-contained (the subagent cannot see this
   conversation):
   ```
   Process type(s) <t1, t2, ...> ONLY. scan_id=<scan_id>, scan_dir=<output_dir>.
   The scan already ran: your types' candidates are in <scan_dir>/report.md and
   <scan_dir>/candidates/<type>/ — do NOT re-run secguard_scan or secguard_plan.
   For each type: load the <type> skill, classify every candidate
   (confirmed/suspected/dismissed), write findings in ONE batch: write `<tmpdir>/<type>.json` with the Write tool, then
   `secguard report --write-json <tmpdir>/<type>.json --scan-id <scan_id> --db <db_path>`.
   Then record A5 reviews for each suspected finding via `secguard report --review --id=<id> ...`. Read source only at reported
   file:line, ≤5 files per type. Report back, per type: confirmed / suspected /
   dismissed counts + the written finding ids.
   ```
   For many types, batch them (give each subagent 3–5 types) instead of one per
   type. Do NOT read `report.md` or all source files yourself — each subagent
   reads only its own types' candidates.
5. **Collect + finalize**: after ALL subagents (or your sequential loop) are
   done, run `secguard report --audit --scan-id <scan_id> --output-dir <output_dir>`
   ONCE to regenerate `result.sarif` + `findings/`. Verify `<output_dir>/result.sarif`
   is non-empty and `findings/` has files; if not, a write did not land — find the
   `per_finding_warning` and fix it.
6. **Report**: emit the Markdown report (报告头 / 摘要 / 总览表 / 问题表 /
   观察项表 / 修复建议 / 逐条详情) per the Output Format, aggregating the
   subagents' returned counts. Reference `result.sarif` and `findings/` only after
   step 5 verified them.

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
