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
ONCE at the very end to regenerate `report.md` (now reflecting confirmed+suspected
verdicts, not candidates) + `result.sarif` + `findings/`. On OpenCode the
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

## Batch Capacity Configuration

> Hard limits governing parallel subagent dispatch. These are NOT advisory —
> the orchestrator must validate every batch against them BEFORE dispatching.

| Parameter | Value | Meaning |
|---|---|---|
| `MAX_TYPES_PER_BATCH` | 4 | Hard ceiling on types assigned to one subagent |
| `MAXTURNS` | 30 | security-auditor.md maxTurns (must match) |
| `MAXTURNS_SAFETY_RATIO` | 0.9 | Use only 90% of maxTurns as the budget |
| `TURNS_PER_TYPE_ESTIMATE` | 6 | Avg turns per type (skill load + classify + write + A5) |
| `LARGE_CANDIDATE_THRESHOLD` | 500 | Types with > this many candidates get a dedicated subagent |

**Pre-dispatch validation (EARS):**
- If a batch has > `MAX_TYPES_PER_BATCH` (4) types, the orchestrator SHALL split it before dispatching.
- Where a single type has > `LARGE_CANDIDATE_THRESHOLD` (500) candidates, the orchestrator SHALL assign that type its own dedicated subagent.
- If `batch_type_count × TURNS_PER_TYPE_ESTIMATE` ≥ `MAXTURNS × MAXTURNS_SAFETY_RATIO` (i.e. ≥ 27), the orchestrator SHALL reject the batch as over-budget and split it.

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

**Candidate-file budget (the biggest time sink — READ THIS).** At this stage
(before `report --audit`), `report.md` is the candidate INDEX: its per-type table
already carries every candidate's `# | Function | File:Line | Variable | Suspicion`.
Never READ the whole `candidates/<type>/NNN_*.md` directory to obtain file:line —
that is a one-file-per-candidate fan-out and, for a type like `null-deref` with
hundreds of confirmed candidates, will burn hundreds of slow READ calls. Open a
`candidates/<type>/NNN_*.md` file ONLY when a `suspected`/`possible` candidate
needs its full evidence block, or a `confirmed` candidate needs a detail `report.md`
does not carry. Classify from the `report.md` table + source at file:line; do not
read a candidate file for every candidate. (`report --audit` later overwrites
`report.md` with the final findings report — the same data source as `result.sarif`.)

**长扫描超时策略 (F4):** Before calling `secguard_scan`, estimate scan duration. If the project has > 100 C files OR the scan is expected to exceed 120s (the default Bash timeout), the orchestrator SHALL either (a) invoke the scan with an explicit timeout ≥ 600s, or (b) use the host's background-task + Monitor mechanism from the start. When a scan is moved to the background, the orchestrator SHALL switch to Monitor within 1 turn — it SHALL NOT use `sleep N; tail` (blocked by Bash safety policy) and SHALL NOT leave a backgrounded scan unmonitored. While the Monitor is pending, the orchestrator SHALL NOT issue parallel Bash commands (the host may buffer their results until the Monitor completes, wasting the parallel window); any preparation (type list, agent-definition read) MUST complete before the Monitor starts.

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

   > **⚠️ 强制约束：当 `total_candidates > 200` 时，禁止选择 SEQUENTIAL 路径。**
   > 违规将导致 orchestrator 上下文在处理完前几个类型后耗尽，其余类型变成
   > "missing-type"，且被错误标注为 "maxturns-exceeded"（子代理从未启动，不存在
   > maxTurns 消耗；正确原因是 "unknown"）。
   >
   > **降级处理：** 当 parallel dispatch 因故不可用（如子代理不可用）且
   > `total_candidates > 200` 时，orchestrator 应明确告知用户"扫描规模超出单代理
   > 能力，需要并行处理支持"，而不可擅自降级为 SEQUENTIAL。
3. **Sequential loop** (the normal path for small scans): for each type with
   candidates > 0, in report.md order — load that type's skill, then classify
   candidates by suspicion_level:
   - **confirmed** → lightweight verify: take file:line from the `report.md` table
     (do NOT read the `candidates/<type>/NNN_*.md` file just to get file:line), then
     verify by viewing the cited source line ±3 lines (do NOT re-derive the dataflow
     or read the whole function), then confirm (match) or dismiss (mismatch). Batch
     all confirmed verdicts into one write call.
   - **suspected/possible** → full reasoning: read candidate evidence, read source
     at reported file:line, reason and classify (confirmed/suspected/dismissed).
   Write findings in ONE batch: write `<tmpdir>/<type>.json` with the Write tool,
   then `secguard report --write-json <tmpdir>/<type>.json --scan-id <scan_id> --db <db_path>`.
   Then A5-review suspected findings, move on. Never skip a type. Obey
   the context budget (≤5 files/type, no full-tree source reads, no skill for a
   0-candidate type).
**调度时序合规规则 (F3):** All subagent dispatches SHALL occur in a single assistant turn — N `Task`/`task` calls issued consecutively with the first-to-last timestamp span ≤ 10s. The orchestrator SHALL NOT split dispatches across turns. After dispatch, while subagents run, the orchestrator SHALL NOT poll their transcripts or issue `sleep`; it SHALL wait for task-notification events.

4. **Parallel dispatch** (ONLY when step 2 says so): validate every batch against the Batch Capacity Configuration above, then spawn one subagent PER BATCH
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
    For each type: load the <type> skill, then classify by suspicion_level:
    - confirmed → take file:line from <scan_dir>/report.md (do NOT read the
      candidates/<type>/NNN_*.md files), verify by viewing the cited source line
      ±3 lines (do NOT re-derive dataflow), confirm/dismiss, batch write.
    - suspected/possible → open only that candidate's evidence file, read source
      at file:line, reason, classify.
    Write findings in ONE batch: write `<tmpdir>/<type>.json` with the Write tool, then
    `secguard report --write-json <tmpdir>/<type>.json --scan-id <scan_id> --db <db_path>`.
   Then record A5 reviews for each suspected finding via `secguard report --review --id=<id> ...`. Read source only at reported
   file:line, ≤5 files per type. Report back, per type: confirmed / suspected /
   dismissed counts + the written finding ids.
   ```
   For many types, batch them — but NEVER exceed `MAX_TYPES_PER_BATCH` (4) types
   per subagent, and validate `batch_type_count × 6 < 27` before dispatching. A
   batch that fails validation SHALL be split. Do NOT read `report.md` or all
   source files yourself — each subagent reads only its own types' candidates.
5. **Collect + finalize**:

   **上报解析与 DB 二次校验 (F5):** For each subagent result, parse by `format_version`:
   - Parseable v1 → record `processed_types` as success, `failed_types` as failed.
   - Unparseable / empty / unknown version → the subagent did not report. Query the DB for its assigned CWEs: `secguard db "SELECT rule_id, COUNT(*) FROM findings WHERE scan_id='<scan_id>' AND rule_id IN (<cwe_list>) GROUP BY rule_id"`. If a type has written > 0, mark it success (data landed despite no report); if 0, mark it failed with `reason: "empty-output"`.
   - A `failed_types` entry with `reason: "api-quota-exhausted"` → mark the type for retry/降级 (see F1 below).

   **重试与降级决策 (F1):** For each subagent marked failed or empty (and DB second-pass did not confirm writes):
   - If retry count < 2, re-dispatch the subagent for the failed types only.
   - If retry count ≥ 2, OR the failure is `api-quota-exhausted` (retrying will hit the same quota wall), do NOT retry — mark the types as `missing-type` and continue. Downgrading to a single-threaded sequential loop is acceptable when ≤ 3 types remain.
   - The orchestrator SHALL NOT finalize while any subagent terminal state is `unknown`.

    **Finalize 前置终态确认 (F1):** Before running audit, confirm every subagent terminal state ∈ {success, failed}. If any is `unknown`, run `secguard status --per-type --scan-id <scan_id>` and use the DB as the authority: types with `terminal_state: "done"` are success; `"in-progress"`/`"pending"` are failed (mark missing-type); `"unknown"` types were never dispatched — mark missing-type with `reason: "unknown"`.

    **Confirmed 异常读源审计 (F6):** Before audit, scan `scan.log` for source-read
    entries associated with confirmed candidates. Classify each read:
    - read range ≤ file:line ±3 lines → "验证性查看" (allowed, no violation).
    - read range far exceeds verification (e.g. whole function/file) → "confirmed
      候选异常读源违规" with type/file/line/read_range.
    - borderline (±3 to ~±10 lines) → "待人工复审".
    If `scan.log` is unavailable, log warning and skip (do not block finalize).

    After ALL subagents (or your sequential loop) are done, run `secguard report --audit --scan-id <scan_id> --output-dir <output_dir>`
   ONCE to regenerate `report.md` (verdict-stage, confirmed+suspected) + `result.sarif`
   + `findings/`. Verify `<output_dir>/result.sarif` is non-empty and `findings/`
   has files; if not, a write did not land — find the `per_finding_warning` and
   fix it.
6. **Report**: emit the Markdown report (报告头 / 摘要 / 总览表 / 问题表 /
   观察项表 / 修复建议 / 逐条详情) per the Output Format, aggregating the
   subagents' returned counts. Reference `report.md`, `result.sarif`, and
   `findings/` only after step 5 verified them.

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
8. 缺失类型章节 (only when types were not successfully processed — F1): a table
   `| 类型 | 候选数 | 失败原因 |` listing every missing-type, with 失败原因 from
   the enum below. This section is MANDATORY when any type was not classified —
   the user must know the scan is incomplete.

   失败原因枚举（含义）:
   - `api-quota-exhausted` – **子代理**触发了 API 配额限制。
   - `maxturns-exceeded` – **子代理**达到了 maxTurns 上限（由 security-auditor.md
     的 steps/maxTurns 参数定义）。
   - `write-busy` – 写报告时 IO 忙。
   - `empty-output` – 子代理执行完成但未产出任何 finding。
   - `unknown` – 类型从未被分发（orchestrator 未启动对应子代理，或 orchestrator
     自身上下文耗尽未完成顺序处理）。

   **注意**：当 orchestrator 自身在顺序处理中耗尽上下文导致类型未处理时，失败原因
   应为 `unknown`（而非 `maxturns-exceeded`），因为 `maxturns-exceeded` 特指子代理
   的 turns 耗尽。

Never include pipeline internals (seed/final/deduped counts, cap, recall,
benchmark, TP/FP, rule_id, whitelist, scan_id, timestamps) in the reply.

## Usage Examples

- Full scan: `/secguard src/`
- Full scan (explicit): `/secguard src/ all`
- Single type: `/secguard src/ buffer-overflow`
- Multiple types: `/secguard src/ double-free,format-string`
- Multiple types (with spaces): `/secguard src/ buffer-overflow, null-deref`
