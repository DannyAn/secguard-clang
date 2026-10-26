Scan the codebase for security vulnerabilities using the SecGuard analysis pipeline.

## Tool Names & Skill Namespace (READ THIS FIRST — these two get confused constantly)

**Which platform am I on?** Two invocation styles exist, and they do NOT mix:

- **OpenCode** — you have MCP tools with underscore names: `secguard_scan`,
  `secguard_plan`, `secguard_report`, `secguard_types`, `secguard_status`,
  `secguard_index`, `secguard_schema`, `secguard_db`, `secguard_metrics`. Use
  those TOOLS, never shell commands.
- **Claude Code (and any shell-only host)** — there are NO `secguard_*` tools.
  Run the `secguard` binary via Bash with a space: `secguard scan`, `secguard
  plan`, `secguard report`, `secguard types`, `secguard status`, `secguard
  metrics`. This doc uses the OpenCode tool names below; translate them to
  `secguard <verb>` on Claude Code.

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

`<db_path>` is `<project>/.codeagent/secguard-clang/.sgre/sgre.db` — the SAME
database the scan wrote. It is the sibling of `<tmpdir>` (`.tmp` and `sgre.db`
live in the same `.sgre/` directory). When you hand a task to a subagent, pass
these as ABSOLUTE paths derived from `<scan_dir>`: `<db_path>` =
`<scan_dir>/../../.sgre/sgre.db`, `<tmpdir>` = `<scan_dir>/../../.sgre/.tmp/` —
never relative paths, because the subagent's working directory is not guaranteed
to be the project root.

`<type>.json` is a JSON ARRAY of finding objects with exactly these keys
(`severity` and `status` are lowercased by the CLI; `confidence` is 0–100):

```json
[
  {"rule_id":"CWE-476","severity":"high","confidence":90,"status":"confirmed",
   "file":"src/a.c","line":42,"function":"f","summary":"...",
   "reasoning":"...","exception_check":"...","fix_strategy":"..."}
]
```

This bare array is the contract. The CLI also accepts a single finding object and
a `{"scan_id": ..., "findings": [...]}` wrapper (so a stray envelope does not lose
the whole type), but write the array — and never mix shapes in one file.

Escaping: every `"` INSIDE a string value must be escaped as `\"`, and any
backslash as `\\`. Do NOT hand-write JSON with unescaped inner quotes — the CLI
will reject it. Prefer writing the JSON file with the Write tool (it does not
escape for you — escape the quotes yourself), then call `--write-json <path>`.

**Fresh-file writes.** The Write tool refuses to overwrite an existing file you
have not Read, so "must read before overwriting" means the file ALREADY exists (a
stale `.tmp` file or your own re-write of a failed chunk) — not that it is
missing. The `.tmp` JSON files are disposable, so never reuse a path: write each
batch to a NEW filename (`<type>.json`, `<type>-2.json`, …) and pass that exact
path to `--write-json`. If a Write still returns "must read before overwriting",
do NOT stop to inspect the directory — just pick the next fresh filename.

Write one `--write-json` per type (all of that type's findings in one array).
The FINAL audit (`report.md` verdict-stage + `result.sarif` + `findings/`) is the
**orchestrator's** single `secguard report --audit --scan-id <scan_id> --output-dir <scan_dir> --ai-duration-ms <ms>`
at the very end (see step 5) — never per chunk, never by a subagent. On OpenCode
the subagents write via the `secguard_report` tool with `finalize: false` (and the
orchestrator's final audit is still that same shell `report --audit --ai-duration-ms`
command; the `secguard_report` tool also accepts `ai_duration_ms` if you finalize
through it).

**Never** re-run a write to "verify" it — the write is idempotent, and `secguard
db` is read-only, so a stray duplicate would force you to edit SQLite by hand.
Verify with `secguard report --audit` (read back findings), not by re-writing.

**Skill names.** Only load skills whose name is EXACTLY a `name` from
`secguard types` (kebab-case, no prefix, no namespace): `buffer-overflow`,
`null-deref`, `crypto-misuse`, etc. The environment may expose other extensions'
skills with prefixed names such as `crs-buffer-overflow`, `crs-crypto-misuse`.
**Never load a prefixed skill** — those belong to another product and do not know
SecGuard's evidence schema. If the only skill you can find is prefixed, STOP and
report it rather than loading the wrong skill. `secguard-clang` is the
**extension/plugin namespace, NOT a skill name** — never call
`Skill("secguard-clang")` or any namespaced skill; the SecGuard skills are the
bare kebab-case type names (e.g. `buffer-overflow`, `null-deref`) under that
namespace.

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
- Partial validation (blacklist only, TOCTOU window) → dismissed.
- No guard + reachable + nullable source + data flow to deref → confirmed.
- **The verdict is BINARY: `confirmed` or `dismissed`.** Only `confirmed` reaches
  `result.sarif` / `result.xlsx` / `report.md` / `findings/`. Everything else —
  a verified false positive (guarded call, safe wrapper, a contract that proves
  safety) OR a candidate you could not settle — is `dismissed` (recorded in the DB
  with reasoning, never shown). "When in doubt" triggers a source read first (≤5
  source-read turns); only after spending that budget may you write `dismissed`,
  with a cited reason. A `confirmed` must be a provable defect.
- **Macro-context candidates (Hint `macro-context`) are the highest false-positive
  risk.** A function-like macro (guard / iterator / accessor / free wrapper) is in
  play, so the pipeline's flow proof may be wrong. Open the candidate's
  `## Code Context` and verify what the macro does before `confirmed`: a NULL/error
  guard macro (`*CHECK*`/`*ASSERT*`/`*RET*`) or a non-null-by-contract iterator/
  accessor → `dismissed`; cannot infer the macro's contract → `dismissed`, never
  `confirmed`. Never confirm a macro-context candidate from the `Source` column
  alone.
- Persist ONLY pipeline-supported types (from `secguard types`); anything else
  goes in the observations table, never through `secguard_report`.

## Source-Path Handling (avoids wasting turns)

`candidates/<type>/_index.md` shows paths relative to the scan target (its
`File:Line` column); the `## Location` block of each
`candidates/<vuln-type>/NNN_*.md` file carries the **absolute** path. Before
reading source, take the absolute path from the candidate file's Location block
and use it directly. Do not reconstruct paths by trial and error.

**Classify only from the candidates + the scan target's own sources.** Do not go
looking for external labels, ground truth, or benchmark/docs files that happen to
sit near the target (e.g. `expected-results.json`, `benchmark.md`,
`assignment-baseline.json`, a previous session log). They are out of scope for a
security scan and reading them makes the verdicts worthless. The scan dir
(`candidates/`, `report.md`) and the target's sources are the only inputs.

## Batch Capacity Configuration

> Hard limits governing parallel subagent dispatch. These are NOT advisory —
> the orchestrator must validate every batch against them BEFORE dispatching.

| Parameter | Value | Meaning |
|---|---|---|
| `MAX_TYPES_PER_BATCH` | 4 | Hard ceiling on types assigned to one subagent |
| `MAX_CANDIDATES_PER_BATCH` | 20 | Hard ceiling on candidates assigned to one subagent (most settle from `Source`+`Hint`; ~20% need one `Evidence` open) |
| `MAXTURNS` | 60 | security-auditor.md maxTurns (reference value — each platform's agent turn cap must still match; NOT used for batch-capacity math, which is count-based) |
| `LARGE_CANDIDATE_THRESHOLD` | 100 | Types with > this many candidates get a dedicated subagent |
| `SPLIT_CANDIDATE_THRESHOLD` | 100 | A type with > this many candidates is SPLIT across multiple subagents, each handling ≤ this many candidates |
| `MAX_EVIDENCE_OPENS_PER_TYPE` | 12 | Evidence-file-open budget per subagent; beyond it the subagent reports `needs_context` instead of opening everything |

`MAX_TYPES_PER_BATCH` / `MAX_CANDIDATES_PER_BATCH` are the ONLY two batch-capacity
knobs — the orchestrator counts types and candidates, no budget formula. A batch
that fits both ceilings is dispatchable; a batch that exceeds either one is split
(split off the heaviest type first, then re-check). `MAXTURNS` remains the
reference value every platform's agent turn cap must match
(`release/check-extension-consistency.py` enforces this), but it is NOT part of the
batch-capacity decision — the count-based ceilings above already keep a batch well
under any platform's turn cap. Auto-confirmed findings are machine verdicts (marked
reviewed at scan time), so they are NOT budgeted or dispatched at all.

**Pre-dispatch validation (EARS):**
- If a batch has > `MAX_TYPES_PER_BATCH` (4) types, the orchestrator SHALL split it before dispatching.
- Where a single type has > `LARGE_CANDIDATE_THRESHOLD` (100) candidates, the orchestrator SHALL assign that type its own dedicated subagent.
- Where a single type has > `SPLIT_CANDIDATE_THRESHOLD` (100) candidates, the orchestrator SHALL split it into MULTIPLE subagents, each handling a ≤100-candidate RANGE of that type (pass the candidate # range, e.g. "candidates #1–100 of null-deref"), so no single subagent's context window is exceeded. Balance the ranges: split into AT LEAST `n = ceil(count / 100)` ranges of `ceil(count / n)` candidates (201 → at least 3 × 67). Smaller ranges are allowed ONLY when the type's per-candidate cost is demonstrably low — a group-verdict-friendly type like null-deref settles most candidates from the `Source`+`Hint` row plus one group judgment per function, without an Evidence open per candidate. Never a sliver tail (100 + 100 + 1): a tiny final range still costs a whole subagent, and every extra range re-reads the `_index.md` and the skill once, so over-splitting burns the same turns it saves. The 100-candidate cap is a CONTEXT ceiling (not a turn ceiling): before the Hint column + Code Context compression, a suspected-heavy range opened an `Evidence` file per suspected candidate and a 100-candidate range could exhaust a 200K context before the tail; with `Source`+`Hint` classification and a ±8 Code Context window the same budget now carries ~2× more, so 100 is the test point — if a super-large function still overflows, the tail is surfaced via the partial-count path, never silently buried.
- The orchestrator SHALL validate a batch against the two capacity ceilings (types,
  candidates) — no budget formula, just counts. A batch that fits both is
  dispatchable; a batch that exceeds either one is split (split off the heaviest
  type first, then re-check). `batch_candidate_count` is the SUM of the batch's
  per-type candidate counts. Auto-confirmed findings carry no unreviewed entries
  (machine verdicts, marked reviewed at scan), so they add nothing to the budget.

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
source files up front. The source-read budget is **≤5 source-read TURNS per
type** — a read at the reported file:line (offset/limit around it), not a
whole-file dump. It is a fixed per-type allowance, and it is per
type — a file you already read for an earlier type is free the second time,
so overlapping types do not multiply the budget.

When a type's candidates span MORE source files than the budget can cover, do NOT
keep opening sources: the `Evidence` file for a candidate embeds that candidate's
own ±8-line `## Code Context`, so open the `Evidence` files for the candidates
that actually need verification instead. Never turn the budget into "read the
whole repo" — on a real codebase that is what exhausts the context window and
leaves the tail candidates unclassified.

**The embedded evidence IS the source — classify from it, and treat a raw `.c`
read as a last resort for what the scan could not embed.** Two kinds of hint, do
NOT conflate them:

- **Machine-proved facts → decisive, no read.** confirm: `certain-null`/
  `null@cfg-proof`/`null@malloc-fail`/`tainted`/constant-`idx@`-past-`cap@`/
  `contract@known`/`leak@definite`/`reason@` weak-crypto/`async-unsafe@`/
  `cast@`(incompatible types). dismiss: `contract@unknown` name-guess,
  `macro-context` unproven macro, `discard`, `src-cap@ ≤ cap@`, `value-shape@`
  placeholder/test.
- **Heuristic observations → keep your judgment** (the ≤5-read budget is the
  backstop when the embedded context cannot settle them): `maybe-null`/
  `maybe-uninit`, `init@unseen` (a cross-function factory/memset may have
  initialized the field — the Code Context does NOT show cross-function writes),
  `taint@none` (judge from the signature whether the argument is a public
  entry-point parameter or internal/trusted), non-literal `fmt-arg@`/`path-arg@`
  (judge the argument's origin), `sanitizer@` (complete whitelist → dismiss,
  partial blacklist → confirm).

A heuristic hint that the embedded context cannot settle is a legitimate use of
the ≤5-turn source-read budget (the WHOLE type's budget, no second round); then
write the verdict with a cited reason. Do NOT load a skill for a type that has 0
candidates.
`candidates/<type>/_index.md` is your primary candidate input (one compact read
per type); the scan summary already gives you the per-type counts.

**Candidate-file budget (the biggest time sink — READ THIS).** At this stage
(before `report --audit`), the candidate index is **per type**: each
`candidates/<type>/_index.md` carries that type's
`# | Function | File:Line | Variable | Suspicion | Hint | Source | Evidence` —
`Source` is the exact statement at file:line, `Hint` is the pipeline's precomputed
verdict facts, and `Evidence` is the EXACT candidate filename
(`NNN_<file>_<line>.md`; use it verbatim, never guess). **The source context is
already embedded for you**: `_index.md` (one-line Source + Hint) and each candidate
file's `## Code Context` (±window). **Do NOT issue a per-candidate source READ** —
that is the single biggest wall-clock cost (one tool round-trip × thousands of
candidates = tens of minutes). A subagent reads ONLY its own type's `_index.md`;
classify from `Source` + `Hint` first, and open the `Evidence` candidate file ONLY
for a `suspected`/`possible` candidate whose Hint is insufficient. (`report --audit`
later overwrites `report.md` with the final findings report — the same data source
as `result.sarif`.)

**Evidence-open budget (P0 — the other dominant cost).** `evidence_opens` is a
budgeted resource, not a default step: a DECISIVE hint settles the row with NO
open. Open an `Evidence` file only for a HEURISTIC token the row cannot settle.
Budget: `MAX_EVIDENCE_OPENS_PER_TYPE` (12) per subagent. A type that needs more
than that is a signal the HINT is under-powered, not that the subagent should
open the whole type: it settles the rest from `Source` + `Hint` with a cited
token and lists the unsettleable candidates in the report's `needs_context`
array; the orchestrator re-dispatches that range ONCE with an explicit
"open the Evidence files, then the ≤5 source reads" prompt. **Leak types are
Hint-decidable**: `leak@definite` + `escape@none` → confirm from the row;
`leak@conditional` → compare `free@N,M` with the row's Source; only
`escape@return|store` + `leak@conditional` needs the Code Context open.

**Group verdict (large suspected types).** Rows sharing `Function` + the same
origin token + `guard@none` are one contract question. Decide the group ONCE
from the first row, then reuse the reasoning for the siblings with
`group:<fn>:<tier>` in each reason. A function whose `proc->profile` is a
non-null contract also dismisses its `proc->ctx` rows; do not re-derive the
contract per row.

**Zero-confirmed shard: skip the write.** If nothing in the type/range is
confirmed, do NOT create a findings file and do NOT call `--write-json`; go
straight to the structured report (`written: 0`).

**长扫描超时策略 (F4):** Before calling `secguard_scan`, estimate scan duration. If the project has > 100 C files OR the scan is expected to exceed 120s (the default Bash timeout), the orchestrator SHALL either (a) invoke the scan with an explicit timeout ≥ 600s, or (b) use the host's background-task + Monitor mechanism from the start. When a scan is moved to the background, the orchestrator SHALL switch to Monitor within 1 turn — it SHALL NOT use `sleep N; tail` (blocked by Bash safety policy) and SHALL NOT leave a backgrounded scan unmonitored. While the Monitor is pending, the orchestrator SHALL NOT issue parallel Bash commands (the host may buffer their results until the Monitor completes, wasting the parallel window); any preparation (type list, agent-definition read) MUST complete before the Monitor starts.

1. **Scan**: call the `secguard_scan` tool with the target path. It returns a
   summary (`scan_id`, `output_dir`, `candidates_by_type`, `auto_confirmed_by_type`,
   `seeds_by_type`, `plan_errors`, `detector_errors`, `total_candidates`, and
   `index_summary` with `files_indexed` / `functions_indexed`). Record `scan_id`,
   `output_dir`, and
   the codebase scale (`files_indexed` files / `functions_indexed` functions) —
   surface the scale in your next message and in the final 报告头. If the summary
   has `report_error`, stop and surface it.
   **`detector_errors`（非空必须上报）:** `secguard_scan` 不再因单个检测器失败而整体
   失败——每个检测器独立跑，失败的会以 `detector_errors`（`检测器名 → 错误`）返回。若
   `detector_errors` 非空，**必须**在最终报告的观察项表里逐条列出（检测器名 + 错误），
   并说明该检测器供给的漏洞类型**候选计数不完整**（含显示 0 的），不得当作"确实无候选"。
   **`candidates_by_type` vs `seeds_by_type`（判定"零候选"根因的权威依据）:** 某类型
   `candidates_by_type == 0` 有两种完全不同的含义——`seeds_by_type == 0` 是**检测器一个
   种子事件都没发出**（该代码库真的没有这类模式，或检测器过窄）；`seeds_by_type > 0` 但
   收敛后为 0 是**过滤链把种子全部淘汰**（可能是过严）。在最终报告的观察项表里，对每个
   0 候选类型按此二分标注，不要含糊地写成"无候选"。
   `secguard_scan` already ran the convergence for EVERY type and wrote
   `report.md` + `candidates/` — do NOT re-run `secguard_plan` or
   `secguard_index` afterward.
2. **Scale gate — pick ONE path and stay on it.** Parallelism has a fixed dispatch
   cost (every subagent re-pays a fresh prompt + skill reloads), but the SEQUENTIAL
   path's wall-clock cost is dominated by PER-TYPE overhead — one skill load + one
   `_index.md` read + one write + one `--write-json` per type ≈ 4 round-trips,
   × 20+ types ≈ 90+ SERIAL round-trips in a single context. That overhead scales
   with **type count**, not candidate count, so a "small" project with many types
   is NOT a small scan. Gate on BOTH axes. Let `type_count` = the number of types
    that need an AI subagent — i.e. `candidates_by_type > 0` in the scan summary.
    `total_candidates` counts only suspected/possible candidates awaiting
    classification. A type with `candidates_by_type == 0` needs NO AI subagent:
    its `auto_confirmed_by_type` findings are machine verdicts already marked
    reviewed at scan time (there is no re-review loop).
   - **`type_count ≤ 3 AND total_candidates ≤ 200` → SEQUENTIAL (step 3).** The
     whole scan is at most one subagent-batch's worth of work; one context avoids
     the dispatch overhead. Do NOT spawn subagents.
   - **otherwise (`type_count ≥ 4` OR `total_candidates > 200`) → PARALLEL
     (step 4).** Serializing many small types is the slow path — a 22-type ×
     8-candidate project ran >30 min sequentially but only a few minutes in
     parallel. Dispatch subagents.

   > **⚠️ 强制约束：当 `total_candidates > 200` 或 `type_count ≥ 4` 时，禁止选择
   > SEQUENTIAL 路径。** 违规将导致 orchestrator 上下文在处理完前几个类型后耗尽，
   > 其余类型变成 "missing-type"，且被错误标注为 "maxturns-exceeded"（子代理从未
   > 启动，不存在 maxTurns 消耗；正确原因是 "unknown"）——即便上下文未耗尽，90+
   > 次串行工具往返也会把墙钟拖到 30 分钟以上。
   >
   > **降级处理：** 当 parallel dispatch 因故不可用（如子代理不可用）且 gate 判定
   > PARALLEL 时，orchestrator 应明确告知用户"扫描规模超出单代理能力，需要并行处理
   > 支持"，而不可擅自降级为 SEQUENTIAL。
3. **Sequential loop** (the normal path for small scans): for each type that needs
    AI work (`candidates_by_type > 0`), load that type's skill.
   type's skill. If `candidates_by_type > 0`, read `candidates/<type>/_index.md`
   and classify by suspicion_level:
   - **confirmed** → read the `_index.md` `Source` column for the statement; confirm
     (matches the evidence) or dismiss (guarded/different) from the table itself.
     Do NOT read source or the candidate file. Batch all confirmed verdicts into
     one write call.
   - **suspected/possible** → classify from the `_index.md` `Source` + `Hint` columns first (Hint: `src@N`/`certain-null`/`maybe-null` (non-null-deref types)/`null@cfg-proof`/`null@malloc-fail`/`null@caller-arg`/`null@opaque-origin`/`null@assumed-return`/`null@external-unknown` (null-deref origin tier)/`tainted`/`taint@none`/`weak-guard`/`divisor@<shape>`/`certain-uninit`/`maybe-uninit`/`api@`/`cat@`/`lhs@`/`rhs@`/`rhs-influenced`/`sink@`/`guard@none`/`macro-context`/`threads@<fn>`/`instances@N`/`write@N`/`mutex@<name>`/`lock@<lo>-<hi>`/`check@<fn>→use@<fn>`/`arg@<expr>`/`may-free`/`reason@<text>`/`key-size@N` (crypto-misuse)/`buf@<name>`/`cap@N`/`idx@<expr>`/`src-cap@N` (buffer-overflow/out-of-bounds)/`alloc@N`/`acquire@N`/`leak@definite`/`leak@conditional`/`escape@none|store|return`/`free@N,M` (leaks)/`range@<interval>`/`callers@<census>` (divide-by-zero)/`origin@<kind>`/`decl@N`/`field@<path>`/`init@none`/`init@unseen`/`init@N`+`may-skip` (uninit; `init@none` = machine-proved never-written stack scalar, `init@unseen` = heap/struct storage a callee/memset/output-param may have initialized — verify the init path, `may-skip` = the only writes are loop-body-only — judge the loop condition)/`expected@<type>`/`actual@<type>`/`cast@<type>` (argument-type/data-representation)/`fmt-arg@<expr>` (format-string)/`path-arg@<expr>` (path-traversal)/`value-shape@<masked>` (hardcoded-secret)/`async-unsafe@<fn>` (signal-handler)/`subject@<name>`/`count-field@<field>`/`evidence-kind@<kind>` (implicit-contract/sizeof-misuse)/`cond@<callee>` (double-free)); for divide-by-zero a `divisor@bare` row is settled from `Source` alone (no evidence open). When the hint is insufficient, open that candidate's `Evidence` file (filename in the `Evidence` column, verbatim; its `## Code Context` already embeds the source, a `contract@unknown` unchecked-return candidate embeds its callee body under `## Callee Definition`, and a null-deref `callee@` candidate embeds the dereferenced callee's body there too) and, if STILL insufficient, a raw source read within the ≤5-read budget — then classify. Only after spending that budget may you write `dismissed` (with a cited reason); never write `dismissed` without reading when the hint was insufficient. A `macro-context` hint means a macro is in play — open the `## Code Context` and verify the macro before `confirmed`.
    Write **confirmed** findings in ONE batch: write `<tmpdir>/<type>.json`
    containing only confirmed findings with the Write tool, then
    `secguard report --write-json <tmpdir>/<type>.json --scan-id <scan_id> --db <db_path>`.
    Dismissed candidates are not written in any batch. After classifying all
    candidates of a type (confirmed written + dismissed not written), call
    `secguard report --complete-type <type> --scan-id <scan_id> --db <db_path>`
    to mark the type's AI stage done (sets ai_stage_status='done'). This is REQUIRED
    for the orchestrator's resume logic (`status --per-type` terminal_state) to
    correctly report `done`.
    Never skip a type. Obey the context budget (no per-candidate source reads).
**调度时序合规规则 (F3):** All subagent dispatches SHALL occur in a single assistant turn — N `Agent`/`task` calls issued consecutively with the first-to-last timestamp span ≤ 10s. (Claude Code's subagent-dispatch tool is `Agent`; older Claude Code versions name it `Task`.) The orchestrator SHALL NOT split dispatches across turns. After dispatch, while subagents run, the orchestrator SHALL NOT poll their transcripts or issue `sleep`.

**子代理返回模型 (F7) — 这是"任务卡住不结束/结果丢失/重复下发"的根因，必读：** 三个平台的返回模型不同，绝不可混用：

- **OpenCode（含 opencode-nga）的 `task` 工具是同步的**：一次 `task` 调用的返回值就是该子代理的最终消息（即 `Structured Report Protocol` 的 JSON 块）。**没有**独立的 "task-notification" 事件可等。因此 orchestrator 在同一个回合里连续发出 N 个 `task` 调用后，这些调用会逐一带回结果；拿到结果后 orchestrator 必须**立刻**进入第 5 步 Collect+finalize，**绝不能**在发出 task 后结束回合去"等通知"——那样这个回合就永远停在原地，任务计时一直走。
- **claude-cac（CodeAgentCLI）的 `Agent` 工具同样是同步的**：一次 `Agent` 调用的返回值就是子代理的最终消息，**没有** `task_notification` 事件。跟 OpenCode 完全一样：N 个 `Agent` 调用逐一带回结果，拿到即进第 5 步；**绝不能**结束回合去"等异步通知"（通知根本不会来，结果就在返回值里，去等会把已落盘的结果丢弃、还误判子代理没跑而重复下发）。
- **Claude Code（官方）的 `Agent`/`Task` 工具是异步的**：子代理在后台运行，通过 `task_notification` 事件回报终态。orchestrator 等待这些事件，直到每个子代理都到达 terminal state，再进入第 5 步。
- **DeepSeek Harness（DSH）的 `subagent` 工具是异步的（continuable）**：一次 `subagent` 调用后台启动一个持久子代理并返回子代理 id（默认 `run_in_background: true`，无需显式传），子代理跑完后 runtime 推送 settlement 通知（含结果 + 最终 assistant 消息）。orchestrator 等这些通知，用 `list_agents` 回忆、`send_message` 追问，直到每个子代理都落地，再进第 5 步；**绝不能**在发出 subagent 后结束回合去"空等"（通知会来，但和官方 Claude Code 一样，拿到全部结果后必须在同一回合内 Collect+finalize）。

**完成契约 (F8) — orchestrator 回合何时结束：** orchestrator 的回合**只有**在发出第 6 步的最终 Markdown 报告之后才允许结束。发出子代理 task 之后：**同步平台（OpenCode / opencode-nga / claude-cac）直接读工具返回值**，**异步平台（官方 Claude Code / DSH）等 `task_notification` / settlement 事件**。拿到所有结果后**必须**在**同一回合**内完成 Collect+finalize（第 5 步）并输出最终报告（第 6 步），然后停止。**禁止**出现"子任务都跑完了、分析也结束了、但没有 finalize、没有最终报告、任务还挂着"的中间态——那等于把已落盘的结果丢弃在后台。

**子代理句柄失效 (F9) — `No task found with ID <id>` 的恢复：** 异步宿主的后台任务句柄偶发被回收，返回 `No task found with ID <id>`。这是宿主侧竞态，**不是扫描失败，也绝不等于该子代理没跑**。遇到时**禁止**反复用同一 ID 重试、禁止死等、禁止把该类型当 `failed` 丢弃。正确动作：立即 `secguard status --per-type --scan-id <scan_id>`，以 DB 的 `terminal_state` 为唯一权威（`done`=成功；`in-progress`/`pending`=未写完；`unknown`=未下发）。对非 `done` 的类型**只重下发缺失部分**（带上候选范围），`done` 的绝不下发。重下发后照常进第 5 步 Collect+finalize，第 6 步出报告。

4. **Parallel dispatch** (ONLY when step 2 says so): validate every batch against the Batch Capacity Configuration above, then spawn one subagent PER BATCH
   of types that need AI work (`candidates_by_type > 0`), ALL IN THE SAME TURN so
   they run concurrently:
   - Claude Code (official): the `Agent` tool (the subagent-dispatch tool; older
     versions name it `Task`) with `subagent_type: "security-auditor"` (bare name).
   - CodeAgentCLI (claude-cac): the same `Agent`/`Task` tool, but this host
     registers plugin agents under their plugin namespace — dispatch with
     `subagent_type: "secguard-clang:security-auditor"`.
   - OpenCode (incl. opencode-nga): the `task` tool with the `security-auditor`
     agent (bare name).
   - DeepSeek Harness (DSH): the `subagent` tool (provider `spawn`), background
     by default — omit `run_in_background` and dispatch all batches in one turn.
   **子代理名解析 (F10) — `Agent type '<name>' not found` 的恢复：** 该错误是
   **名字不匹配**，不是扫描失败。遇到时**禁止**用同名原样重试、**禁止**用空参数重发
   （会触发宿主 loop 检测被拦截）、**禁止**把该类型标 `missing-type`、**禁止**降级为
   orchestrator 顺序自理。正确动作：读错误消息里的 `Available agents:` 列表，选出以
   `security-auditor` 结尾的条目（裸名或 `<plugin>:security-auditor` 形态），**同一回合**
   用该精确名重发全部失败的批次，然后照常进第 5 步 Collect+finalize。
   Each subagent prompt must be self-contained (the subagent cannot see this
   conversation):
   ```
   RED LINE: you are a SUBAGENT. Never call `secguard report --complete-type`
   or `secguard report --audit` (the orchestrator is the single writer of
   ai_stage_status), and never re-run secguard scan/plan/index.

   Process type(s) <t1, t2, ...> ONLY. scan_id=<scan_id>, scan_dir=<output_dir>.
   (If a type is split by candidate RANGE, e.g. "null-deref #1-100", classify ONLY
   those candidates — the # column in <scan_dir>/candidates/<type>/_index.md — and
   leave the rest to sibling subagents.)
   The scan already ran: your type's candidates are in
   <scan_dir>/candidates/<type>/_index.md and <scan_dir>/candidates/<type>/NNN_*.md
   — do NOT re-run secguard_scan or secguard_plan. The source is already embedded:
   `_index.md` has a `Source` column per candidate (the exact statement), a `Hint`
   column (the pipeline's precomputed verdict facts: `src@N`/`certain-null`/
   `maybe-null` (non-null-deref types)/`null@cfg-proof`/`null@malloc-fail`/
   `null@caller-arg`/`null@opaque-origin`/`null@assumed-return`/`null@external-unknown` (null-deref origin tier)/`tainted`/`taint@none`/`weak-guard`/`divisor@<shape>`/`certain-uninit`/`maybe-uninit`/`api@`/`cat@`/`lhs@`/`rhs@`/`rhs-influenced`/`sink@`/`guard@none`/`macro-context`/`threads@<fn>`/`write@N`/`lock@<lo>-<hi>`/`check@<fn>→use@<fn>`/`reason@<text>`/`key-size@N`/`buf@<name>`/`cap@N`/`idx@<expr>`/`src-cap@N`/`alloc@N`/`acquire@N`/`leak@definite`/`leak@conditional`/`escape@none|store|return`/`range@<interval>`/`callers@<census>`/`origin@<kind>`/`decl@N`/`field@<path>`/`init@none`/`init@unseen`/`init@N`+`may-skip`/`expected@<type>`/`actual@<type>`/`cast@<type>`/`fmt-arg@<expr>`/`path-arg@<expr>`/`value-shape@<masked>`/`async-unsafe@<fn>`/`subject@<name>`/`count-field@<field>`/`evidence-kind@<kind>`/`cond@<callee>`), plus an `Evidence` column naming the exact
   candidate file, and each candidate file has a `## Code Context` block — do NOT
   issue per-candidate source READs (that is the tens-of-minutes cost). Read ONLY
   your type's `_index.md`, never the whole report.md.
    For each type: load the <type> skill, then classify by suspicion_level:
    - confirmed → read the `Source` column in <scan_dir>/candidates/<type>/_index.md
      (do NOT read the candidate files and do NOT open source), confirm/dismiss from
      that statement, batch write.
    - suspected/possible → classify from the `Source` + `Hint` columns FIRST. `Hint`
      is the pipeline's precomputed facts (`src@N` = null-source line, `certain-null`
      = definitely null, `maybe-null` = possibly null, `tainted` = injection source,
       `taint@none` = the pipeline found NO taint chain reaching the sink — this is
       NOT 'proven safe': a bare parameter/global or chained call may still be
       caller-controlled, so judge the argument's origin from the signature,
       `weak-guard` = partial guard, `certain-uninit`/`maybe-uninit` = uninit tier,
       `field@<path>` = the uninit read target is that member/element, NOT the base
       pointer, `init@none` = the detector PROVED a stack scalar is never written
       before the read (confirm from the row), `init@unseen` = heap/struct storage a
       callee/memset/output-param may have initialized (verify the init path, do NOT
       confirm from it alone), `init@N`+`may-skip` = the only writes are
       loop-body-only — judge the loop condition, nothing else,
      `null@cfg-proof` = CFG-proved NULL reaches the deref (machine-proved),
      `null@malloc-fail` = proven-nullable call result (allocator / libc /
      return-NULL callee; `callee@` names an embedded body when defined in scan),
       `null@caller-arg` = unproven caller argument, `null@opaque-origin` =
       opaque external contract (an external caller's argument / a field value of
       an externally-defined type — fail-open assumption, judge the external
       contract), `null@assumed-return` = fail-open callee-return assumption (the
       callee returns a parameter / field / unknown call; its body is embedded
       under `## Callee Definition` — judge it there), `null@external-unknown` =
       fail-open external assumption — verify or dismiss,
      `api@<name>` = the API in play, `cat@<name>` = the detector category,
      `contract@known`/`contract@unknown` = unchecked-return callee contract,
      `discard` = the return value is stored then `(void)`-cast away (a
      deliberate discard — the failure is unobservable, dismiss from the row),
      `threads@<fn>`/`write@N` = shared-data race, `lock@<lo>-<hi>` = TOCTOU
      critical section, `check@<fn>→use@<fn>` = TOCTOU check/use pair,
      `macro-context` = a function-like macro is in play — verify it before
      confirming, `reason@<text>` = crypto-misuse detector rationale (judge
      from it, not the API name alone), `key-size@N` = declared key bytes
      (under 16 is below the modern-cipher minimum),       `buf@<name>`/`cap@N`/
      `idx@<expr>` = buffer-overflow/out-of-bounds buffer, capacity, and
      access index/copy size/declared size argument (a constant past cap@ is
      detector-proved; a variable one needs your range judgment),
      `src-cap@N` = the SOURCE buffer's known capacity (a `strcpy(g_dst, g_src)`
      with src-cap@ ≤ cap@ copies a bounded source into a same-or-larger
      destination — dismiss from the row, no read), `alloc@N`/`acquire@N` =
      the leak's allocation/acquisition line, `leak@definite` = no
      release/escape/transfer reachable on any path (machine-proved loss),
      `leak@conditional` = a release channel exists but the CFG proved a
      leak path bypasses it, `escape@none|store|return` = the
      ownership-transfer channel state, `free@N,M` = the release sites
      that exist but do not cover the leak path. For
      divide-by-zero, `Hint` is `divisor@<shape>`
      (`bare` = a plain identifier, `call` = a call result, `compound` = a complex
      expression; `field`/`global` are already auto-confirmed and never reach you):
      a `divisor@bare` row is settled from the `Source` column alone (an unguarded
      plain divisor → `dismissed`) with NO evidence-file open. Open that candidate's
      `Evidence` file (filename in the `Evidence` column, verbatim; its
      `## Code Context` embeds the source) ONLY when the hint is insufficient to
      decide — a `certain-null` + `src@N` hint (or null-deref's `null@cfg-proof`)
      usually settles the verdict with no
      file open, and a `divisor@call`/`divisor@compound` hint is the only
      divide-by-zero shape that needs the open. A decisive hint is a verdict:
      `contract@unknown` / `macro-context` / `maybe-null` (no provable source)
      → `dismissed` from the row, citing the token; `init@unseen` and
      `taint@none` narrow the question to "was the field initialized by a
      callee?" / "is the argument caller-supplied?" — judge that from the
      embedded signature/context. Only when the row has NO decisive or narrowing
      fact do you open the source (within the ≤5 source-read budget) to settle
      it, then write the verdict with a cited reason — never write `dismissed`
      without a decisive/narrowing fact AND without reading.
    `## Code Context` is a ±8-line window around the reported line for most types,
    but **integer-overflow** embeds the WHOLE function span (signature → candidate,
    up to ~200 lines) because its verdict needs the parameter types, the entry
    guard, and the accumulation chain — facts a ±8 window cannot show. Either way
    it never exceeds ~200 lines, so opening it cannot exhaust your context, and a
    large function is NOT a reason to classify from the `Source` column alone.
    A complex function is exactly where careful analysis matters most: classify
    from `Source` + `Hint` + the Code Context window first, and when that is
    insufficient, spend the ≤5 source-read budget reading the SPECIFIC lines the
    `Hint` names (the free / guard / return / source line) via offset/limit —
    never paste the whole function, which is both unfocused and what actually
    overflows the window. Read a big function MORE carefully, never less.
    A `contract@unknown` unchecked-return candidate also carries a
    `## Callee Definition` section with the callee's body (in-scan callees only):
    judge the failure sentinel there — do NOT spend a source read on a body the
    evidence already shows.
    Derive the DB and the write dir from <scan_dir> (ABSOLUTE, never relative):
    - DB:  <scan_dir>/../../.sgre/sgre.db
    - tmp: <scan_dir>/../../.sgre/.tmp/
    Write findings in ≤200-finding chunks (a ≤100-candidate range is exactly ONE
    chunk — never split a range into multiple files; a ≤200 array of compact
    Source+Hint verdicts stays well under context, so the tail is never dropped).
    For each chunk: write a FRESH `<scan_dir>/../../.sgre/.tmp/<type>-partN.json`
    with the Write tool (N increasing; if a Write returns "must read before
    overwriting", do NOT stop to inspect the directory — just use the next fresh
    filename), then persist it immediately before starting the next chunk:
    - If the `secguard_report` MCP tool is in your toolset (OpenCode / OpenCode-NGA),
      call it with the `findings` array and `finalize: false` (do NOT use Bash, and
      do NOT call `--complete-type` — the orchestrator marks types complete in
      step 5). The write is idempotent, so partial progress is safe.
    - Otherwise (Claude Code / Claude CAC shell-only host), run
      `secguard report --write-json <scan_dir>/../../.sgre/.tmp/<type>-partN.json --scan-id <scan_id> --db <scan_dir>/../../.sgre/sgre.db`
      with Bash. Do NOT call `--complete-type` — it is the orchestrator's
      single-writer step (step 5); a subagent call races it and can flip the
      terminal state under the orchestrator. Report `processed_types` instead.
      If nothing in the range is confirmed, skip the write entirely.
    Report back, per type: confirmed count + the written finding ids. Dismissed
    count is not persisted (not counted, not reported). Emit the Structured
    Report Protocol block; if the ≤12 Evidence-open / ≤5 source-read budget could
    not settle some candidates, list them in `needs_context` instead of opening
    the whole type.
   ```
   **Shell note when scripting the dispatch:** never prefix a loop with
   `VAR=... for ...` (`VAR=x for i in ...` is a shell syntax error); export the
   variable or set it inside the loop body.

   For many types, batch them — but NEVER exceed `MAX_TYPES_PER_BATCH` (4) types
   per subagent, and validate the capacity ceilings before dispatching:
   `batch_type_count ≤ MAX_TYPES_PER_BATCH` (4) AND `batch_candidate_count ≤
    MAX_CANDIDATES_PER_BATCH` (20). `batch_candidate_count` is the SUM of the
   batch's per-type candidate counts. A batch that fails any ceiling SHALL be
   split (split off the heaviest type first). Do NOT read `report.md` or all
   source files yourself — each subagent reads only its own types' candidates.
5. **Collect + finalize**:

   **DB schema 速查 (列名别猜 — 猜一个不存在的列如 `f.type` 会白费 1~2 轮 `secguard schema` 往返):**
   Prefer structured tools over raw SQL — every count you need already has one:
    - per-type candidate/written → `secguard status --per-type --scan-id <id>` (`candidate_count`/`written_count`/`auto_confirmed`/`terminal_state`, no SQL). `auto_confirmed` findings are machine verdicts (marked reviewed at scan time) — they need no AI review.
    - per-type verdict split → `secguard report --audit --scan-id <id> --output-dir <dir>` returns an `audits` array (`vuln_type`/`confirmed`/`auto_confirmed`/`ai_stage_status`; `dismissed` and `suspected` are not present — dismissed candidates are not persisted). `ai_stage_status` values: `pending` (AI stage not done), `done` (AI stage complete), `failed` (AI stage failed, reserved). Sum that array for the report — do NOT raw-query `findings` to recompute it.
    **findings/ 里的 confirmed 文件 ≠ 子代理报告的 confirmed（auto-confirmed 已落库）:** `findings/<type>/NNN_*_confirmed.md` 是两类之和——(a) `auto-confirmed`：pipeline 在 scan 阶段直接机器确认的确定性发现（divide-by-zero 的 `divisor@field`/`global`、null-deref 的 `null@cfg-proof`/`null@malloc-fail`、uninit 的 certain-uninit 等），它们**不在** `candidates/_index.md` 里、子代理从来看不到；(b) 子代理写的 `confirmed`。所以 findings/ 的 confirmed 文件数可以明显大于子代理报告的数，多出的就是 auto-confirmed，**不是漏报也不是子代理说错**。最终计数一律以 `report --audit` 的 `audits` 数组（含 `auto_confirmed` 字段）为准，不要 `ls findings/` 反推、不要为这个对账。
   **DB 路径（绝对路径，否则 Exit code 1）:** every `secguard db` / `secguard schema` / `secguard report` call that takes `--db` MUST pass the ABSOLUTE path `<scan_dir>/../../.sgre/sgre.db`. A relative `.sgre/sgre.db` fails with `Error: Exit code 1` whenever your cwd is not the project root — do NOT retry it as-is; re-run with the ABSOLUTE path. **Do NOT `cd` into the scan dir to "fix" it:** commands run WITHOUT `--db` (`secguard plan`/`status`/`metrics`/`query` and `report --audit`) resolve the DB relative to cwd, so cd'ing into the scan dir would mint a second, empty `sgre.db` under the scan dir (doubling build time and splitting findings across two databases). Keep cwd at the project root for the whole run.
    **dismissed 不持久化，`final_count − confirmed` 不是漏写:** dismissed candidates are intentionally NOT persisted (no finding row, no count). When `ai_stage_status='done'` for a type, the AI has processed all candidates — the `final_count − confirmed` gap is the dismissed count, which is normal, not a missing write. When `ai_stage_status='pending'` the type is in-progress (reported by `status --per-type`, not as unclassified). Because `--write-json` UPSERTs keyed on `(scan_id, rule_id, file, line, function, variable)`, candidates for the SAME variable at the SAME file:line:function collapse into ONE finding. Do NOT inspect the schema or raw-query `findings` to "persist" dismissed; trust `secguard status --per-type --scan-id <id>` (`written_count`/`terminal_state`/`ai_stage_status`) instead.
   If you MUST raw-query, run `secguard schema <table>` first, or use these exact names — never guess:
    - `findings`: `id, rule_id (CWE, e.g. CWE-476 — there is NO type/vuln_type column), severity, status (confirmed|auto-confirmed for new scans; legacy dismissed/suspected rows tolerated but ignored), file_path (NOT file), line_number (NOT line), function_name, scan_id, review_status`
       **终报/问题表查询必须过滤 `review_status`:** an auto-confirmed finding
       carries `review_status='confirmed'` (machine verdict, no re-review). If a
       later pass ever downgrades one to `dismissed`, a raw `SELECT ... FROM
       findings` would still count it as present, so any final-total query must
       add `AND (review_status IS NULL OR review_status NOT IN ('dismissed'))` —
       or use `report --list --status confirmed` (which applies `EffectiveStatus`)
       instead of raw SQL.
    - `scan_stats`: `scan_id, vuln_type (kebab-case type name), seed_count, final_count, ai_stage_status (pending|done|failed)`

   **上报解析与 DB 二次校验 (F5):** For each subagent result, parse by `format_version`
   to know which types it was ASSIGNED, which it reports as FINISHED
   (`processed_types`), and which it reports as ABANDONED (`failed_types`, with a
   `reason`). Do NOT trust the self-reported `reason` or counts — the LLM
   misreports (e.g. a Bash-permission misjudgment reported as
   `api-quota-exhausted`, or dismissed candidates counted into `written`). The DB
   is the SOLE authority for "did data land"; the subagent's processed/failed
   split is the only signal for "did it FINISH", because **dismissed candidates
   are NOT persisted — `written_count < candidate_count` is NORMAL whenever
   anything was dismissed, never a missing write by itself.** For EVERY assigned
   type, run `secguard status --per-type --scan-id <scan_id>` and decide by
   `terminal_state` (the authoritative signal) + `candidate_count` + `written_count`
   (NOT the raw `findings` count, which cannot tell "no candidates" from
   "candidates but never written"):
   - `candidate_count == 0` → the type had nothing to classify → `done` (success), NEVER failed.
   - Subagent reports the type FINISHED (`processed_types`) → run `--complete-type`
     for it FIRST (the orchestrator's step, below), then re-read `terminal_state`:
     `done` = full success — the `candidate_count − written_count` gap is the
     DISMISSED count (normal, not persisted). NEVER judge this PARTIAL.
   - Subagent reports the type ABANDONED (`failed_types`), or never reports it
     finished → decide by DB `written_count`:
       - `written_count == 0` → FAILED with `reason: "empty-output"` (data did NOT
         land), regardless of the subagent's self-reported reason.
       - `written_count > 0` → PARTIAL (context-overflow): `candidate_count −
         written_count` candidates were never written. Surface the gap in the
         观察项表 (`| <type> | context-overflow 未落库 N 条 |`), do NOT re-dispatch.

   **失败降级决策 (F1):** For each FAILED type (`candidate_count > 0 && written_count == 0`):
   - **Recover by re-dispatch first, not by sequential self-classification.** A `written_count == 0` type was almost always NEVER STARTED (a sibling type overflowed the subagent's context before it was reached), so its candidates are untouched. Dispatch ONE fresh single-type subagent per leftover type (single type, FULL candidate range) in a single turn — a fresh subagent has a full context window and will not overflow — then re-run the F5 DB check for that type before proceeding. **Do NOT fall back to classifying the leftover types yourself in sequence** — that serial loop is the 3–5-minute wall-clock cost this rule removes. (Guard: a type whose `terminal_state` is already `done` but `written_count == 0` means "all candidates dismissed", which is SUCCESS, not a leftover — do not re-dispatch it.)
   - Only when a subagent is unavailable (parallel dispatch cannot run) OR the re-dispatched subagent AGAIN lands `written_count == 0`, mark the type `missing-type` with the DB-derived `reason` and CONTINUE. A `0 < written_count < candidate_count` type (mid-type `context-overflow`) is NOT re-dispatched — a re-run overflows again on the same super-large function; surface that gap in the 观察项表 instead.
   - The orchestrator SHALL NOT run `report --audit` while ANY type still has `candidate_count > 0 && written_count == 0` and is not yet marked `missing-type` — auditing now silently drops those unclassified candidates from `report.md`/`result.sarif` and fakes a complete scan. Mark every such type `missing-type` (after the ONE re-dispatch attempt) BEFORE audit.
   - The orchestrator SHALL NOT finalize while any subagent terminal state is `unknown`.

    **Finalize 前置终态确认 (F1):** Before running audit, confirm every subagent terminal state ∈ {success, failed}. If any is `unknown`, run `secguard status --per-type --scan-id <scan_id>` and use the DB as the authority: types with `terminal_state: "done"` are success; `"in-progress"`/`"pending"` are failed (mark missing-type); `"unknown"` types were never dispatched — mark missing-type with `reason: "unknown"`.

    **读源审计 (F6):** Before audit, scan the subagent transcripts / `scan.log` for
    source-read + Evidence-open entries. Check BOTH directions — the recall
    direction is the one that bites:
    - Confirmed over-read (precision): a confirmed candidate whose read range far
      exceeds verification (whole function/file instead of ±3 lines) → "confirmed
      候选异常读源违规" with type/file/line/read_range. (≤ ±3 lines = 验证性查看, allowed;
      borderline ±3~±10 = 待人工复审.)
    - Dismissed without reading (recall): a `dismissed` candidate whose reason is a
      bare "insufficient context" and that shows NO Evidence-open and NO source-read
      → "未研判即弃" (bailed without reading). Surface it distinctly in the 观察项表,
      and re-dispatch that candidate ONCE with an explicit "open the Evidence file,
      then the ≤5 source reads, before you may write dismissed" prompt. The reason
      contract (agent-body) makes this checkable: a valid dismissed reason always
      cites the file:line-range or Evidence file it read.
    If the transcript/`scan.log` is unavailable, log warning and skip (do not block finalize).
    On OpenCode the orchestrator cannot see a subagent's INTERNAL tool calls (the
    `task` return is only the subagent's final message), so F6 there degrades to
    the subagent's self-reported `source_reads`/`evidence_opens` counts (see the
    Structured Report Protocol in agent-body): mark any type whose self-report
    exceeds a budget (`source_reads > 5`, `evidence_opens > 12`, or a
    dismissed-without-read pattern) in the 观察项表 as "读源审计受限（无
    transcript）" rather than claiming a verified audit. Do not treat the missing
    transcript as proof of compliance. An over-budget `evidence_opens` is a
    TRIAGE-STRATEGY signal (the Hint was under-used), not a recall failure — do
    not re-dispatch for it; note it and move on.

    **`needs_context` 二次下发:** if a subagent reports `needs_context`, the
    orchestrator re-dispatches EXACTLY those candidate `#`s ONCE (one subagent,
    same type, explicit "open the Evidence files, then the ≤5 source reads,
    before you may write dismissed"), then re-runs the F5 DB check for that type.
    Do not re-dispatch a whole type for a handful of `needs_context` entries and
    do not silently drop them — a dropped entry is an unclassified candidate.

    After you have verified the subagent writes against the DB and before the
    final audit, run `secguard report --complete-type <type> --scan-id <scan_id>
    --db <db_path>` for every type the subagent reported FINISHED
    (`processed_types`). This is the ORCHESTRATOR's step — a single writer of
    `ai_stage_status` keeps the terminal state authoritative (subagents MUST NOT
    call it themselves, per step 4); skipping it leaves the type's
    `ai_stage_status` as `pending`, which F5 would then misread as incomplete. A
    type the subagent reported ABANDONED (`failed_types`) is NOT marked complete
    — it goes through the F5 FAILED/PARTIAL branch instead.

    **Auto-confirmed findings are machine verdicts — verified ONCE, never
    re-classified in a loop:** the scan writes them `status='auto-confirmed'`
    (with `review_status='confirmed'`) straight into `findings`, so they are NOT
    in `candidates/_index.md` and the audit would ship them unexamined. A
    machine proof is only as good as its premise, and production measured a 75%
    false-positive rate on the `uninit` tier (macro for-init writes, block-scope
    `extern` declarations, output-parameter fills). Step 5.5 below is the
    bounded verification pass for exactly those rows; it is NOT the removed
    per-candidate re-review loop (no `--list-auto-confirmed`, no completeness
    gate, no re-derivation of every proof). The final free-form judgment is
    still done by the SAME AI agent (the security-auditor subagent's own LLM) as
    it classifies candidates — there is NO separate or customer-configured LLM
    anywhere in the pipeline.

    After ALL subagents (or your sequential loop) are done, run `secguard report --audit --scan-id <scan_id> --output-dir <output_dir> --ai-duration-ms <ms>`
   ONCE to regenerate `report.md` (verdict-stage, confirmed only) + `result.sarif`
   + `findings/`. `<ms>` is the MEASURED AI-classification wall-clock (from
   `secguard_scan` returning / entering the Scale gate, to this finalize step) in
   milliseconds — it is persisted to `scan_runs.ai_duration_ms` so production runs
   can report pipeline-vs-AI timing. Verify `<output_dir>/result.sarif` is
   non-empty and `findings/` has files; if not, a write did not land — find the
   `per_finding_warning` and fix it.

   **Step 5.5 — 机器判定终审复核（让 `result.sarif` 直接可提单）:** run ONCE per
   scan, AFTER the audit above. Scope = ONLY the rows the pipeline proved by itself
   (`status='auto-confirmed'`); candidates the AI already classified are done.

   a. List them (absolute DB path; the `findings` table is the documented query
      surface): `secguard db "SELECT id, rule_id, file_path, line_number,
      function_name, variable, properties FROM findings WHERE
      scan_id='<scan_id>' AND status='auto-confirmed' ORDER BY id" --db <abs db>`.
      `properties` already carries the proof basis
      (`auto_confirm_evidence` / `auto_confirm_hint_tokens` /
      `auto_confirm_verdict_facts`).
   b. Judge each row against its type's machine-proof PREMISE. Settle it from the
      row whenever possible and open the source only when the row cannot:

      | CWE | premise the machine proof assumes | dismiss when |
      |---|---|---|
      | CWE-457 uninit | `certain-uninit` / `init@none` = "never written" | the variable is written by a macro (`macro-context` in its hints, or its name appears in a macro invocation in the window), is a block-scope `extern`/`static`, is passed as `&var` to a callee (`init@unseen`), or the struct is written field-by-field before the read |
      | CWE-476 null-deref | `null@cfg-proof` = "NULL reaches on every path" | the dereference sits in a macro that may assign the pointer (an iteration macro's loop header) |
      | CWE-134 format-string | a non-literal format reaches a sink | every in-tree caller of the format parameter passes a literal (`callsites@N:all-literal`) |
      | CWE-369 divide-by-zero | a proved-zero / non-zero-constant divisor | a zero guard sits in the ±8-line window before the division |
      | other | the proof class named in the row's facts | a concrete `file:line` in the source contradicts the premise |

   c. Write the dismissals in ONE batch (no per-row subprocess), every reason citing
      a `file:line` fact: `secguard report --review-json <file.json> --db <abs db>`
      with `[{"id":<id>,"review_status":"dismissed","review_reasoning":"<file:line +
      why-safe>"}]`. A row you keep needs NO write.
   d. Re-run the audit ONCE so `result.sarif` / `report.md` / `findings/` reflect the
      dismissals — the regenerated `result.sarif` is the deliverable.
   e. Budget: bounded. With more than ~40 machine findings, verify the
      assignment-based premises first (CWE-457 / CWE-476) and record the remainder as
      "machine verdicts unverified" in the report's limitations. Never read source for
      a row the checklist above settles from the row itself.

   **`summary` — 全轮汇总的唯一权威（控制台/最终报告不要自己相加 `audits`）:** the
   audit response carries `summary`, the scan-wide aggregate that the per-type
   `audits` array lacks (the console used to show per-type confirmed/dismissed
   counts with no total). Read the aggregate from it verbatim:
   `scale` / `files_indexed` / `functions_indexed` / `lines_of_code`（规模）,
   `raw_seeds` / `converged_candidates`（收敛前→后；**这两个只用于内部核对，
   不得写进给用户的最终回复**——见 Output Format 末尾的"不要暴露流水线内部量"）,
   `auto_confirmed` / `ai_confirmed` / `confirmed_total`（`confirmed_total` 已含
   auto-confirmed，**不是**二者再相加）, `dismissed_total` /
   `actionable_total`（= `confirmed_total`；裁决是二元的，suspected 已不存在）,
   `unclassified_candidates`, `types_scanned` / `types_with_findings`,
   `automated_analysis_ms` / `ai_classification_ms`, and `headline`.
   `summary` 与 `report.md`/`audit-report.md` 是同一份数据的三处渲染，**一律以
   `summary` 为准**；自行推算出的数字一旦与 `report.md` 不一致，就是错的。

6. **Report**: emit the Markdown report (报告头 / 摘要 / 总览表 / 问题表 /
   观察项表) per the Output Format, aggregating the
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
   d. Cross-reference: ≤5 source-read turns, absolute paths from the candidate
      Location block.
   e. **WRITE now**: `secguard_report` with `findings` for THIS type, passing
      `scan_id` + `output_dir`. Every candidate gets a verdict (confirmed /
      dismissed); a candidate you cannot settle from the embedded evidence is read
      first (≤5 source-read turns), then dismissed with a cited reason — never
      dismissed unread. Confirmed findings carry `reasoning` + `exception_check` +
      `fix_strategy`. Handle `per_finding_warning` before moving on.
3. **Finalize and verify**: after the loop, read `<output_dir>/result.sarif`
   (non-empty) and list `<output_dir>/findings/` to confirm your verdicts
   landed; if not, fix the failing write before reporting.
4. Report for the selected types only (报告头 / 摘要 / 总览表 / 问题表), note
   skipped/failed types, reference `result.sarif` only after verifying it. The
   摘要 paragraph is MANDATORY here too: use the same
   `本轮扫描确认 <X> 个问题。` sentence,
   restricted to the selected types (state explicitly that the scope is a type
   subset, so the numbers are not read as a full-scan verdict).

## Output Format (final reply to the user)

Report the diagnostic conclusion in Chinese, Markdown tables only:

1. 报告头: `代码仓：<repo abs path>；扫描目录：<scanned dir abs path>；规模：<N> 文件 / <M> 函数 / <L> 行`。**规模三个数一律取自 `secguard_scan` 的 `index_summary`（`files_indexed`/`functions_indexed`）与 `report --audit` 的 `summary`（`lines_of_code`）；任一项缺失就写"未统计"，不要留空、不要估算**。**必须给出三个时间口径（用于生产反馈与分析，勿估算，抓真实墙钟）**：
   - `自动分析耗时 ≈ <scan_metrics.duration_ms/1000> 秒`（`secguard scan` 二进制自身墙钟：索引 + 建图 + 检测 + 多层过滤收敛 + 机器 auto-confirm + 出候选报告，**不含 AI Agent 研判**）。
   - `AI 研判耗时 = <秒>`（**实测**：从 `secguard_scan` 返回、进入第 2 步 Scale gate 起，到第 6 步出最终报告为止的墙钟；用你的工具计时，不要估算）。
   - `端到端耗时 = <秒>`（自动分析 + AI 研判 + 编排调度开销）。
   **不要用"流水线"描述时间**："流水线/收敛"是**候选数量**概念（raw seeds → 层层过滤 → final），不是时间口径；把二进制耗时说成"流水线耗时"既漏了 AI 研判这一环、又和"扫描耗时"语义打架，才会出现"10 分钟 vs 3~4 小时"的误会。
2. 摘要（**必须，独立成段，位于总览表之前**）: 先给一句全轮汇总，再给确认数的构成，例如
   `本轮扫描确认 <X> 个问题。其中 <X1> 个由流水线自动确认、<X2> 个由 AI 研判确认；已排除 <D> 个（误报或无法判定）。`
   - `<X>` = `summary.confirmed_total`（**已含 auto-confirmed**）；`<X1>` = `summary.auto_confirmed`；`<X2>` = `summary.ai_confirmed`；`<D>` = `summary.dismissed_total`。`summary.actionable_total` 等于 `confirmed_total`（只有 confirmed 计入 actionable）。
   - **禁止**用 `audits` 数组自行相加、禁止用 `ls findings/` 反推：`findings/` 的 confirmed 文件数 = auto-confirmed + AI confirmed，多加出来的那部分不是漏报。
   - 若 `<X> == 0`：写 `本轮扫描未确认任何问题（<D> 项候选已排除）。`——**不要**省略本段。
   - 若 `summary.unclassified_candidates > 0`，在摘要后补一句 `另有 <U> 项候选未落库判定，见观察项表。`
3. 总览表: `| Skill | 类别 | 确认 | 已排除 |`，末行加 `| **合计** | | **<X>** | **<D>** |`（数字须与第 2 段摘要完全一致）
4. 问题表: `| Skill | 文件:行号 | 函数 | 严重度 | 结论 | 说明 |` (confirmed only)
5. 观察项表 (if some types were not persisted): `| Skill | 说明 |`
   **异常必须对用户可见：** 任何空回（`state=completed` 且 `task_result` 为空）、
   整波重派、或 `failed_types` 重派事件都必须在观察项表里各占一行（类型 + 发生了什么 +
   是否已恢复），不得静默吸收——重派占掉的墙钟（第二波 turn）用户有权知道。
6. 缺失类型章节 (only when types were not successfully processed — F1): a table
   `| 类型 | 候选数 | 失败原因 |` listing every missing-type, with 失败原因 from
   the enum below. This section is MANDATORY when any type was not classified —
   the user must know the scan is incomplete.

   失败原因枚举（含义）:
   - `api-quota-exhausted` – **子代理**触发了 API 配额限制。
   - `maxturns-exceeded` – **子代理**达到了 maxTurns 上限（由 security-auditor.md
     的 steps/maxTurns 参数定义）。
   - `context-overflow` – **子代理**处理大类型时上下文/token 先于步数耗尽，
     已处理部分候选但尾部候选被静默截断（区别于 `maxturns-exceeded`：token 耗尽
     ≠ 步数耗尽）。
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
