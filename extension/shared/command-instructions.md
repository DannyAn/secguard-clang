Scan the codebase for security vulnerabilities using the SecGuard analysis pipeline.

## Tool Names & Skill Namespace (READ THIS FIRST — these two get confused constantly)

**Which platform am I on?** Two invocation styles exist, and they do NOT mix:

- **OpenCode** — you have MCP tools with underscore names: `secguard_scan`,
  `secguard_plan`, `secguard_report`, `secguard_review`, `secguard_types`,
  `secguard_status`, `secguard_index`, `secguard_schema`, `secguard_db`,
  `secguard_metrics`. Use those TOOLS, never shell commands.
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
own runtime temp dir, NOT `/tmp`. The scan step creates it if absent but does
**not** clear it at scan start (a crashed scan's settlement payloads are kept for
inspection/replay — issue #238 §3.3). So never assume a `<type>.json` path is
free: write every batch to a fresh, scan-unique filename
(`<type>-<scan_suffix>.json`) and pass that exact path to `--write-json`. If a
Write returns "must read before overwriting", just pick the next fresh filename —
do not stop to inspect or delete the directory.
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
**orchestrator's** single `secguard report --audit --scan-id <scan_id> --output-dir <scan_dir>`
at the very end (see step 5) — never per chunk, never by a subagent. The engine
**self-measures** the AI stage from the settlement reports' timestamps (total +
per type), so do NOT hand-estimate a wall clock: `--ai-duration-ms <ms>` is ONLY
an override for a host that cannot write settlement files. On OpenCode the
subagents write via the `secguard_report` tool with `finalize: false` (and the
orchestrator's final audit is still that same shell `report --audit` command; the
`secguard_report` tool also accepts `ai_duration_ms` if you finalize through it,
with the same override-only meaning).

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
- **Weak crypto is context-dependent, not "confirmed, period".** CWE-327 is
  defined by the USE, not the algorithm alone: DES/3DES/RC4/MD5/SHA-1/`rand()`
  are weak primitives, but a password hash / signature is **confirmed** (fix =
  AES-256 / SHA-256 / a CSPRNG) while MD5-for-checksum or `rand()`-for-UI/test
  is **dismissed**. Judge the use from the `reason@` hint + Code Context.
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
| `MAX_CANDIDATES_PER_BATCH` | adaptive (see below) | Per-type candidate ceiling: `min(⌊MAX_EVIDENCE_OPENS_PER_TYPE / r_type⌋, ⌊(CONTEXT_BUDGET − skill − legend) / per_candidate_index_token⌋)`, never a hardcoded constant |
| `MAXTURNS` | 60 | security-auditor.md maxTurns (reference value — each platform's agent turn cap must still match; NOT used for batch-capacity math, which is count-based) |
| `LARGE_CANDIDATE_THRESHOLD` | 100 | Types with > this many candidates get a dedicated subagent |
| `SPLIT_CANDIDATE_THRESHOLD` | 100 | A type with > this many candidates is SPLIT across multiple subagents, each handling ≤ this many candidates |
| `MAX_EVIDENCE_OPENS_PER_TYPE` | 12 | Evidence-file-open budget per subagent; beyond it the subagent reports `needs_context` instead of opening everything (hard constraint, `agent-body.md`) |
| `CONTEXT_BUDGET` | 98000 | Subagent context window reserved for data (conservative 128K window − 30K reasoning/write reserve). Covers Claude Code (200K), OpenCode, DSH with margin. The only external input; lower it if a host has a smaller window. |
| `HOST_AGENT_TIMEOUT` | 660 | synchronous-host `Agent`/`task` hard ceiling (seconds; OpenCode / opencode-nga). A force-rejected batch feeds back into r_type (raise r → smaller next batch), NOT a hard pre-dispatch cap. |
| `SMALL_TYPE_SEQUENTIAL_THRESHOLD` | ≤15 candidates | A type with ≤15 candidates AND no whole-function-embedding member is cheaper for the orchestrator to classify directly than to dispatch (no skill-load/spawn fixed cost) |

`MAX_CANDIDATES_PER_BATCH` is **adaptive, per-type, and dual-constrained** — it is
NOT a hardcoded 20. The two constraints, both measurable at scan time:

1. **Evidence-open budget** (`agent-body.md` hard value 12): a batch of N candidates
   opens `N × r_type` Evidence files in expectation, so `N ≤ ⌊12 / r_type⌋`.
   `r_type` = `sum(evidence_opens) / sum(range_candidates)` from prior settlement
   reports (`agent-body.md` `evidence_opens` field). First run with no history:
   `r_type = 0.30` (conservative default for heavy types; lighter types self-correct
   after one scan).
2. **Context-token budget**: the subagent reads `skill + legend + N × per_candidate_index_token`,
   so `N ≤ ⌊(CONTEXT_BUDGET − skill − legend) / per_candidate_index_token⌋`.
   `per_candidate_index_token` = `_index.md` shard byte size / candidate count / 4
   (scan-time measurable: `writeTypeIndex` knows both). `skill` + `legend` are the
   type's SKILL.md + the `_index.md` legend, both known at scan time.

`N_type = min(constraint1, constraint2, 100)`. Constraint 1 binds for heavy types
(null-deref/memory-leak: high r → small N); constraint 2 binds for light types
(divide-by-zero `divisor@bare`: low r → large N would overflow context via the
index read itself). The prior hardcoded 20 violated neither proof nor measurement
— it was an unvalidated constant that caused 1980 candidates → 98 batches →
10 serial waves on a 10-wide host (production: "scanned for a day").

**Evidence volume is part of constraint 2, not a footnote:** the context a batch
actually consumes is `skill + legend + N × per_candidate_index_token +
N × r_type × per_evidence_open_bytes`. For a line-level type the Evidence is a
±8-line window (small); for a whole-function-embedding (heavy) type it is the
whole function (~200 lines, 10–25× the window), so the heavy type's N must use
that whole-function byte estimate, and heavy types always get dedicated batches.

**The 12-open budget is per SUBAGENT (per batch), never per type:** a mixed batch
of 4 types shares ONE pool of 12 Evidence opens (sum over its types), which is
also what the settlement `evidence_opens` entries and the F6 audit sum over a
batch's `processed_types` measure. Interpreting it as "12 per type" quadruples
the intended I/O and wall clock.

**Mandatory-evidence types have a hard capacity floor:** a type whose SKILL
requires opening Code Context for EVERY candidate before confirming (e.g.
divide-by-zero's divisor shapes) has effective `r_type = 1`, so its batch is
capped at 12 from the FIRST run — the `r_type = 0.30` first-run default does not
apply to it, and its needs_context second pass is re-split by the SAME capacity
formula (never "one residual batch, once").

`SPLIT_CANDIDATE_THRESHOLD=100` remains a **context** ceiling for ranging: a type
over 100 is split into ≤100-candidate ranges for context, and EACH range is then
dispatched in ≤`N_type`-candidate batches. `MAXTURNS` remains the
reference value every platform's agent turn cap must match
(`release/check-extension-consistency.py` enforces this), but it is NOT part of the
batch-capacity decision — the count-based ceilings above already keep a batch well
under any platform's turn cap. Auto-confirmed findings are machine verdicts (marked
reviewed at scan time), so they are NOT budgeted or dispatched at all.

`SMALL_TYPE_SEQUENTIAL_THRESHOLD` = **≤15 candidates**: a type with ≤15 candidates and
NO whole-function-embedding member (integer-overflow embeds the whole function span
up to ~200 lines — 10–25× the evidence volume of line-level types) is cheaper for
the orchestrator to classify directly (no skill-load / subagent-spawn fixed cost)
than to dispatch. Production: the orchestrator classified 9 small-type candidates
in ~5 minutes while a 12-candidate two-heavy-skill subagent batch ran 36 minutes —
the subagent's fixed cost (two skills + whole-function evidence) exceeded the
classification itself. Only dispatch such a type when the orchestrator is already
saturated or the type needs a source read it cannot afford; never fold a
whole-function-embedding type into a "small" batch to dodge the threshold.

**Whole-function-embedding (heavy) types — grouping rule:** `integer-overflow` (and
`argument-type` if it ever embeds whole spans) is a HEAVY skill: its per-candidate
Evidence is the whole function, and its verdict needs parameter types + entry guard
+ accumulation chain. **A heavy type gets a DEDICATED batch: it SHALL NOT share a
batch with ANY other type (light or heavy).** Its candidate ceiling is the
context-budget constraint using the WHOLE-FUNCTION evidence volume (see the
`evidence_bytes` term below), not the evidence-open constraint — its `r_type`
understates cost because the index row is a single line while the Evidence file
is the whole function.

The B1 types `stack-address-escape` / `invalid-free` / `switch-fallthrough` are
LIGHT (line-level ±8-line evidence) and participate in the existing grouping
rules as light types — treat them like any other light type, do not re-derive a
new capacity class for an unfamiliar name.

**Pre-dispatch validation (EARS):**
- If a batch has > `MAX_TYPES_PER_BATCH` (4) types, the orchestrator SHALL split it before dispatching.
- A batch containing a whole-function-embedding (heavy) type (`integer-overflow`) SHALL contain ONLY that type (a heavy type gets a dedicated batch, never shared with any light or heavy type) — its per-candidate evidence is the whole function, so counting it like a line-level type under-budgets the batch.
- Where a single type has > `LARGE_CANDIDATE_THRESHOLD` (100) candidates, the orchestrator SHALL give that type dedicated subagent(s) — never share it with another type — and split those subagents by the next rule.
- Where a single type has > `SPLIT_CANDIDATE_THRESHOLD` (100) candidates, split it into ≤100-candidate RANGES for context (pass the candidate # range, e.g. "candidates #1–100 of null-deref"). Then dispatch **each range in ≤`N_type`-candidate subagent batches** where `N_type` is the adaptive per-type ceiling above. Balance ranges so there is no sliver tail (100 + 100 + 1): merge a final range smaller than 5 into its predecessor and re-split evenly. If a super-large function still overflows a batch, surface the tail via the partial-count path, never silently bury it.
- The orchestrator SHALL validate a batch against the two capacity ceilings (types,
  candidates) — no budget formula, just counts. A batch that fits both is
  dispatchable; a batch that exceeds either one is split (split off the heaviest
  type first, then re-check). `batch_candidate_count` is the SUM of the batch's
  per-type candidate counts, and SHALL be ≤ `N_type` (computed with the batch's
  heaviest type's `r_type` — each type's own count also individually ≤ its own
  `N_type`). Auto-confirmed findings carry no unreviewed entries
  (machine verdicts, reviewed once in Step 5.5), so they add nothing to the budget.
- **Feedback (F11 → r_type):** when a batch is force-rejected by `HOST_AGENT_TIMEOUT`,
  the orchestrator SHALL raise `r_type` for that type (the batch was more expensive
  than the historical rate predicted) and re-dispatch a smaller batch. This is
  feedback control, not a pre-dispatch hard cap — the 660s wall depends on code
  shape (super-large functions), not a static per-candidate cost.
- **Large-light + tiny packing (P1-5):** a LIGHT type with > 30 candidates (e.g.
  `dangerous-function`) MAY share a batch with up to 3 TINY light types (≤ 3
  candidates each) to fill `MAX_TYPES_PER_BATCH` instead of occupying a batch
  alone. The large type's candidates dominate the budget, but the tiny types add
  negligible evidence volume (their ≤ 3 candidates each cost one `_index.md` +
  a handful of Evidence files). This is a packing optimization, never a reason to
  exceed the type/candidate ceilings.
- **Sync-host small-type strategy (P1-6):** `SMALL_TYPE_SEQUENTIAL_THRESHOLD`
  (≤ 15 candidates → orchestrator classifies directly) applies ONLY on hosts
  where the orchestrator can classify WHILE subagents run (asynchronous: official
  Claude Code / claude-cac / DSH). On a SYNCHRONOUS host (OpenCode / opencode-nga)
  the orchestrator is BLOCKED inside each `Agent`/`task` call and cannot do its own
  classification concurrently, so the threshold is DISABLED there: pack the small
  types into parallel batches per the packing rule above instead of dispatching
  them as separate subagents or classifying them serially.

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
  `maybe-uninit`, `init@error-path` (an in-tree callee writes the storage only
  on some paths and the caller discards its return — `init-writer@` names the
  callee; judge that skipped-write path), `init@branch` (a write exists only
  inside a conditional branch), `taint@none` (judge from the signature whether
  the argument is a public entry-point parameter or internal/trusted),
  non-literal `fmt-arg@`/`path-arg@` (judge the argument's origin), `sanitizer@`
  (complete whitelist → dismiss, partial blacklist → confirm).

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

**Group verdict (large suspected types).** Rows may share a verdict ONLY when
`Function` + origin token + `chain-root` are all identical (+ `guard@none`); then
they are one contract question. Decide the group ONCE from the first row, then
reuse the reasoning for the siblings with `group:<fn>:<tier>:<chain-root>` in
each reason. A function whose `proc->profile` is a non-null contract also
dismisses its `proc->ctx` rows; do not re-derive the contract per row. **The
`chain-root` dimension is NOT optional:** rows in the same function with
different `chain-root@` (or carrying `sibling-callers@`) are NOT one group — a
guard on one entry chain does not protect the sinks reached through another, so
judge every distinct chain independently (see the `sibling-callers@` hint rule).
Reusing one chain's guard to dismiss another chain is a recall bug, not a valid
group verdict.

**Zero-confirmed shard: write the dismissed rows, not nothing.** If nothing in
the type/range is confirmed, still call `--write-json` with the array of
`status: "dismissed"` rows (`findings_written: 0` is a healthy response) — the
`candidate_verdicts` ledger is the only way recovery tells "all dismissed" from
"never ran". Skip the write ONLY when the range had zero candidates.

**长扫描超时策略 (F4):** Before calling `secguard_scan`, estimate scan duration. If the project has > 100 C files OR the scan is expected to exceed 120s (the default Bash timeout), the orchestrator SHALL either (a) invoke the scan with an explicit timeout ≥ 600s, or (b) use the host's background-task + Monitor mechanism from the start. When a scan is moved to the background, the orchestrator SHALL switch to Monitor within 1 turn — it SHALL NOT use `sleep N; tail` (blocked by Bash safety policy) and SHALL NOT leave a backgrounded scan unmonitored. While the Monitor is pending, the orchestrator SHALL NOT issue parallel Bash commands (the host may buffer their results until the Monitor completes, wasting the parallel window); any preparation (type list, agent-definition read) MUST complete before the Monitor starts.

1. **Scan**: call the `secguard_scan` tool with the target path. It returns a
   summary (`scan_id`, `output_dir`, `candidates_by_type`, `auto_confirmed_by_type`,
   `seeds_by_type`, `plan_errors`, `detector_errors`, `detectors_skipped`, `total_candidates`, and
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
   **`detectors_skipped`（非空必须说明）:** 某仓库通过 `[scan] skip_detectors` /
   `--skip-detectors` 关掉检测器时，这些检测器供给的类型会显示 0 候选——这是**开关**，
   不是"干净"；在观察项表里按该字段标注，不要当成"该类型没有这类模式"。
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
    its `auto_confirmed_by_type` findings are machine verdicts written with
    `review_status` NULL — they await Step 5.5's review, not a per-candidate
    subagent loop.
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
   - **suspected/possible** → classify from the `_index.md` `Source` + `Hint` columns first (Hint: `src@N`/`certain-null`/`maybe-null` (non-null-deref types)/`null@cfg-proof`/`null@malloc-fail`/`null@caller-arg`/`null@callback-entry`/`null@opaque-origin`/`null@global-null`/`null@assumed-return`/`null@external-unknown`/`array-buffer@<count-field>` (null-deref origin tier; `null@callback-entry` = function registered via function-pointer (ADDR_TAKEN) with zero direct call sites — parameter nullability bound to the registration-site context; a boundary scan pre-dismisses it unless a `caller-null@` witness exists; `array-buffer@` = a count-gated array buffer — `count == 0 ⇒ buffer NULL/empty`, confirm when the chain dereferences it without checking the count field)/`chain-root@<fn>`+`sibling-callers@<fn1,fn2>` (the candidate's caller chain + the OTHER chains that also call the same function — a guard on a sibling chain does NOT protect this candidate)/`tainted`/`taint@none`/`weak-guard`/`divisor@<shape>`/`certain-uninit`/`maybe-uninit`/`api@`/`cat@`/`struct@<name>`/`alloc-size@<N>`/`layout-field@<name>:<off>+<size>` (layout_oob_read/write; default-ABI layout — verify packing/ABI before confirming)/`lhs@`/`rhs@`/`rhs-influenced`/`sink@`/`guard@none`/`macro-context`/`macro@<name>`/`threads@<fn>`/`instances@N`/`write@N`/`mutex@<name>`/`lock@<lo>-<hi>`/`check@<fn>→use@<fn>`/`arg@<expr>`/`may-free`/`reason@<text>`/`key-size@N` (crypto-misuse)/`buf@<name>`/`cap@N`/`idx@<expr>`/`src-cap@N` (buffer-overflow/out-of-bounds)/`alloc@N`/`acquire@N`/`leak@definite`/`leak@conditional`/`escape@none|store|return`/`free@N,M` (leaks)/`range@<interval>`/`callers@<census>` (divide-by-zero)/`callsites@<census>` (format-string/path-traversal; `N:all-literal` = every in-tree caller passes a compile-time constant)/`origin@<kind>`/`decl@N`/`field@<path>`/`init@none`/`init@error-path`/`init-writer@<callee>:<line>`/`init@branch`/`init@N`+`may-skip` (uninit; `init@none` = machine-proved never-written stack scalar, `init@error-path` = an in-tree callee's early return skips the write and the caller discards the return — judge that path, `may-skip` = the only writes are loop-body-only — judge the loop condition)/`expected@<type>`/`actual@<type>`/`cast@<type>` (argument-type/data-representation)/`fmt-arg@<expr>` (format-string)/`path-arg@<expr>` (path-traversal)/`value-shape@<masked>` (hardcoded-secret)/`async-unsafe@<fn>` (signal-handler)/`subject@<name>`/`count-field@<field>`/`evidence-kind@<kind>`/`sibling-guard@<fn>:<line>` (implicit-contract/sizeof-misuse; only `evidence-kind@sibling` — a same-file sibling — is kept, `self`/`sibling-weak` are pre-dismissed)/`cond@<callee>` (double-free)); for divide-by-zero a `divisor@bare` row is settled from `Source` alone (no evidence open). When the hint is insufficient, open that candidate's `Evidence` file (filename in the `Evidence` column, verbatim; its `## Code Context` already embeds the source, a `contract@unknown` unchecked-return candidate embeds its callee body under `## Callee Definition`, and a null-deref `callee@` candidate embeds the dereferenced callee's body there too) and, if STILL insufficient, a raw source read within the ≤5-read budget — then classify. Only after spending that budget may you write `dismissed` (with a cited reason); never write `dismissed` without reading when the hint was insufficient. A `macro-context` or `macro@<name>` hint means a macro is in play — read the embedded `## Macro Definition` (or `secguard_def` when it is not embedded) and verify the macro before `confirmed`; never grep the repo for it.
    Write **confirmed + dismissed** verdicts in ONE batch: write `<tmpdir>/<type>.json`
    containing every classified candidate (confirmed rows AND `status:"dismissed"`
    rows with `reasoning`) with the Write tool, then
    `secguard report --write-json <tmpdir>/<type>.json --scan-id <scan_id> --db <db_path>`.
    Confirmed rows land in `findings`; dismissed rows land in the
    `candidate_verdicts` ledger so recovery can tell "classified and dismissed"
    from "never classified" — omitting dismissed rows leaves the type's
    `remaining` permanently > 0. After classifying all candidates of a type, do NOT
    call `secguard report --complete-type` from the subagent — the orchestrator
    marks types done in step 5 when absorbing reports. Report `processed_types`
    in your Structured Report Protocol block instead; the orchestrator's resume
    logic reads that.
    Never skip a type. Obey the context budget (no per-candidate source reads).
**调度时序合规规则 (F3):** All subagent dispatches SHALL occur in a single assistant turn — N `Agent`/`task` calls issued consecutively with the first-to-last timestamp span ≤ 10s. (Claude Code's subagent-dispatch tool is `Agent`; older Claude Code versions name it `Task`.) The orchestrator SHALL NOT split dispatches across turns. After dispatch, while subagents run, the orchestrator SHALL NOT poll their transcripts or issue `sleep`.

**滑动窗口补位 (F3a) — 消灭整波 barrier（P0-1）：** F3 的"所有派发 ≤10s"只约束**首波**。首波发出后，每收到**一个**批次的完成信号（官方 Claude Code 的 `task_notification`、DSH 的 settlement 通知；或同步宿主若其 `Agent`/`task` 工具支持 `run_in_background` 时的完成通知），编排器**立即**吸收该批次 settlement 并**立即**补派积压队列中的下一个批次——不等其他在跑批次，并发数始终顶满宿主上限，波间空档与 straggler 尾部空转消失。补位派发按通知逐个发，**显式豁免 F3 的 ≤10s 限制**。吸收顺序与 F11 一致：`secguard status --reports`（有 `valid:true` 覆盖则吸收 `written`/`dismissed`/`needs_context` 并 `report --complete-type`）→ `secguard status --per-type`（读引擎预计算的 `already_covered_ranges` 与 `in_flight_ranges`，只补派真正缺失且无人占位的 range；补派前先按 F13 claim）。同步宿主若其 `Agent`/`task` 无后台模式（OpenCode / opencode-nga 按 F7 的同步返回），则首波仍按 F3 一次性发出、超时走 F11——退化为现状，无回归。**complete-type 的调用时机（覆盖派生后必看）：** 引擎已把类型完成改为**派生**——`status --reports` 吸收 settlement 时自动按 range 覆盖判定并写 `ai_stage_status='done'`；`report --complete-type` 现在先做覆盖校验：该类型还有 `uncovered_ranges`、活跃 claim 或 needs_context 时会返回 `status:"incomplete"`（退出码 1）。因此**每吸收一个 range 就调 complete-type 是错误用法**：只在 `status --per-type` 显示该类型 `remaining:0` 且无 `in_flight_ranges` 后才调用（或依赖吸收时的自动派生，不再显式调用）。complete-type 不再替你把别人的在途 claim 伪结算为 done。

**F3a 的可执行实现（in-flight 计数器 + 宿主并发上限查询）：** F3a 不是"应当"级建议，是必须执行的状态机。编排器在本轮开始时**显式**维护两个量：(1) `host_max` = 宿主允许的最大并发子代理数；(2) `in_flight` = 当前已发出但未收到完成信号的批次计数。

- **`host_max` 取值（禁止试探）**：本轮开始先读引擎给出的上限——`secguard status --show-limits`（OpenCode：`secguard_status {show_limits:true}`）的 `ai_stage.host_max_concurrency`，默认 10（Claude Code / DSH），部署可设 `SECGUARD_AI_HOST_MAX_CONCURRENCY` 覆盖；首波直接按该值发出。不要"先派 10 个、被拒 4 个、再补 4 个"。仅当宿主**仍然**拒绝并返回 `Cannot spawn subagent: session already has N running subagent(s) ... reaching the maximum allowed N`（或等价错误）时，才把 `host_max` 置为该错误里的 `N`、把被拒批次放回队列头——这是兜底，不是首选探测。**一旦 `host_max` 确定，后续所有补位都以 `in_flight < host_max` 为准，绝不再试探。**
- **`in_flight` 维护**：首波一次性发出 `min(积压批次总数, host_max)` 个批次，`in_flight` 置为该数。此后**每收到一个完成信号**：先按 F11 吸收该批 settlement（`status --reports` 的 `valid:true` 覆盖；吸收时引擎已在同一事务里把该 type 的 `ai_stage_status` 标为 `done`，`--complete-type` 只是通知丢失或旧库的修复路径）→ `in_flight -= 1` → 若积压队列非空，**在同一响应轮内**立即发出下一个批次并 `in_flight += 1`。**禁止**"收完一整波再派下一波"——那正是整波 barrier 的成因。
- **worker 心跳/进度（替代 mtime 猜测）**：liveness 信号因宿主而异——**OpenCode MCP 宿主**：子代理通过 `secguard_report` 工具直写 DB，**不落 chunk 文件**，liveness = `status --per-type` 的 `written_count` 在两次查询（间隔 >30s）间是否有增长；**shell-only 宿主**：子代理按 heartbeat 契约每 ~10 个候选刷新一次 `<subagent_id>-chunk-<k>.json`，liveness = chunk 文件 mtime。`status --reports` 对每条报告返回 `heartbeat_age_ms`、`stalled`（超过 `ai_stage.heartbeat_stall_ms`，默认 15 分钟未再落盘）和 `progress`（`classified` / `total` / `percent`）。`stalled=false` 或 `progress.classified` 仍在增长或 `written_count` 有增长就是「慢但在跑」，**不得**据此判死或重派；只有 `stalled=true` **且** `written_count` 无增长（F11 的一次复核，两次查询间隔 >30s）才允许按缺失 range 重派。
- **判定完成的标准**：一个批次"完成"= 收到宿主通知（异步宿主）/ `Agent` 调用正常返回（同步宿主）/ 落盘报告 `valid:true` 覆盖（通知丢失时按 F9）。三种信号等价，任一到达即触发补位，不要只等一种。

**子代理返回模型 (F7) — 这是"任务卡住不结束/结果丢失/重复下发"的根因，必读：** 三个平台的返回模型不同，绝不可混用：

- **OpenCode（含 opencode-nga）的 `task` 工具是同步的**：一次 `task` 调用的返回值就是该子代理的最终消息（即 `Structured Report Protocol` 的 JSON 块）。**没有**独立的 "task-notification" 事件可等。因此 orchestrator 在同一个回合里连续发出 N 个 `task` 调用后，这些调用会逐一带回结果。**同步宿主的唯一调度状态机（超 host_max 队列的唯一合规路径）：每波返回后先按 F3a 吸收 settlement 并补派下一波（`in_flight < host_max` 就继续发），只有「积压队列为空 AND in_flight 为 0 AND `status --per-type` 的 `uncovered_ranges` 全空 AND 无 `in_flight_ranges`」全部成立时才进入第 5 步 Collect+finalize。严禁"首波 N 个返回就立刻 finalize"——那是把积压批次流程性放弃；也严禁在发出 task 后结束回合去"等通知"——那样这个回合就永远停在原地，任务计时一直走。**
- **claude-cac（CodeAgentCLI）的 `Agent` 工具是异步的**：一次 `Agent` 调用返回 `Async agent launched successfully` + `agentId`，子代理在后台运行、完成后才推送通知（生产冒烟实测：返回的是 agentId 而非最终消息）。因此发出 N 个 `Agent` 调用后**不能**按同步假设直接进 Collect——拿不到结果；必须像官方 Claude Code 一样等每个子代理的完成通知（或读 `<tmpdir>/<subagent_id>-report.json` 落盘报告），再进第 5 步。**防御性写法（F7a）**：不同宿主版本/配置下返回形状可能漂移，发出第一个 `Agent`/`task` 后先探测其返回——含 `agentId` 且带 "background/async" 字样即为异步宿主（等通知/落盘），直接返回最终消息 JSON 即为同步宿主（读返回值）；把探测结果记在心里，后续 N−1 个调用与 Collect 阶段照此办理，不要先验地假定同步或异步。
- **Claude Code（官方）的 `Agent`/`Task` 工具是异步的**：子代理在后台运行，通过 `task_notification` 事件回报终态。orchestrator 等待这些事件，直到每个子代理都到达 terminal state，再进入第 5 步。
- **DeepSeek Harness（DSH）的 `subagent` 工具是异步的（continuable）**：一次 `subagent` 调用后台启动一个持久子代理并返回子代理 id（默认 `run_in_background: true`，无需显式传），子代理跑完后 runtime 推送 settlement 通知（含结果 + 最终 assistant 消息）。orchestrator 等这些通知，用 `list_agents` 回忆、`send_message` 追问，直到每个子代理都落地，再进第 5 步；**绝不能**在发出 subagent 后结束回合去"空等"（通知会来，但和官方 Claude Code 一样，拿到全部结果后必须在同一回合内 Collect+finalize）。

**完成契约 (F8) — orchestrator 回合何时结束：** orchestrator 的回合**只有**在发出第 6 步的最终 Markdown 报告之后才允许结束。发出子代理 task 之后：**同步平台（OpenCode / opencode-nga）在调用正常返回时直接读工具返回值**；**若调用被宿主超时 force-reject，则改走 F11 的落盘报告恢复，不得据此重派**；**异步平台（官方 Claude Code / claude-cac / DSH）等 `task_notification` / settlement / 完成通知事件（或读落盘报告）**。拿到所有结果后**必须**在**同一回合**内完成 Collect+finalize（第 5 步）并输出最终报告（第 6 步），然后停止。**禁止**出现"子任务都跑完了、分析也结束了、但没有 finalize、没有最终报告、任务还挂着"的中间态——那等于把已落盘的结果丢弃在后台。

**子代理句柄失效 (F9) — `No task found with ID <id>` 的恢复：** 异步宿主的后台任务句柄偶发被回收，返回 `No task found with ID <id>`。这是宿主侧竞态，**不是扫描失败，也绝不等于该子代理没跑**。遇到时**禁止**反复用同一 ID 重试、禁止死等、禁止把该类型当 `failed` 丢弃。正确动作：先读该子代理落盘的结构化报告 `<tmpdir>/<subagent_id>-report.json`（子代理按 O2 在最终消息前写入，承载消息里没有的 `needs_context`/`dismissed` 明细），再 `secguard status --per-type --scan-id <scan_id>`，以 DB 的 `terminal_state` 为唯一权威（`done`=成功；`in-progress`/`pending`=未写完；`unknown`=未下发）。对非 `done` 的类型**只重下发缺失部分**（带上候选范围，先按 F13 claim；`claimed:false` 则不重发），`done` 的绝不下发。重下发后照常进第 5 步 Collect+finalize，第 6 步出报告。

**Agent 调用超时 (F11) — `Tool call hung for 660000ms` / force-reject：** 同步宿主（OpenCode / opencode-nga）的 `Agent`/`task` 调用是同步的，单调用有硬上限（约 660s）。security-auditor 的一个批次（skill 加载 + `_index.md` + Evidence 打开 + JSON 写入）可能超过它；宿主会 force-reject 该调用，但**子代理仍在后台继续跑，并会按 O2 把 `<tmpdir>/<subagent_id>-report.json` 落盘**。因此超时是**宿主超时，不是批次失败**，**禁止**仅凭超时就重派。恢复顺序：
1. `secguard status --reports --scan-id <scan_id>`（OpenCode 用 `secguard_status` 的 `reports: true`）——列出已落盘报告的 `subagent_id` / `scan_id` / `processed_types`（含 `range`）/ `needs_context` / `valid`，以及存活信号 `heartbeat_age_ms` / `stalled` / `progress`。
2. 若有 `valid:true` 的报告覆盖该批次（scan_id 相同 + type/range 匹配）：吸收其 `written`/`dismissed`/`needs_context`，对 `processed_types` 调 `report --complete-type`，**绝不重派**。
3. 若暂无 `valid` 报告：`secguard status --per-type --scan-id <scan_id>`；若 `written_count` 有增长或 `terminal_state=done`，在同一回合内先吸收其他已完成批次/补派积压，再查一次 `--reports`；`valid:false`（部分写入）表示子代理还在写，**继续处理其他批次，不重派**。
4. 只有在**一次复核后仍无 valid 报告且无进展**时，才重派，且只重派缺失的 type/range（先按 F13 claim，`claimed:false` 则不重发），绝不整批重来。

**中断恢复 (F11b) — 用户切换/turn 打断后子代理状态不可知：** F11 处理的是**超时**（660s force-reject，子代理仍在后台跑）；**中断**（用户切换 turn / 宿主被打断）是不同场景——子代理可能被杀。中断后恢复顺序：
1. `secguard status --per-type --scan-id <scan_id>` + `secguard status --reports --scan-id <scan_id>`，获取每个 in-flight type 的 `written_count` / `dismissed_count` / `terminal_state` 和已有 settlement 报告。
2. 对有 `valid:true` 报告的 type → 吸收（F11 第 2 步）。
3. 对 `written_count + dismissed_count == candidate_count` 的 type → 全部分类完，调 `--complete-type` 标记 done。
4. 对 `written_count == 0` 且无 settlement 的 type → 子代理被杀前未写任何数据，**立即重派**（先 F13 claim，`claimed:false` reason `stale` 则接管；reason `held` 但 `age_ms > 600000`（10 min）且无 heartbeat 增长 → 用 `--reclaim` 强制接管）。
5. 对 `0 < written_count < candidate_count` 且无 settlement 的 type → 子代理被杀前写了部分数据，**只重派缺失 range**（`candidate_count - written_count - dismissed_count` 个候选）。
6. **禁止**等 claim TTL 30 min——中断后子代理大概率已死，用 `written_count` 两次查询（间隔 >30s）无增长作为 dead 判据，不用 claim TTL。

**派发前落点检查 (F11a)：** 任何派发之前先跑 `secguard status --reports --scan-id <scan_id>`，跳过已被 `valid:true` 报告覆盖的 type/range；再跑 `secguard status --per-type --scan-id <scan_id>`，跳过 `already_covered_ranges`（已完成）与 `in_flight_ranges`（有活 claim）里的 range。然后对剩余每个批次按 F13 claim，只有 `claimed:true` 才派发。这样超时后的 re-plan 是幂等的，重复派发一个已完成或已在跑的批次是纯重复劳动。

**派发原子占位 (F13) — 先占位再派发，消灭同类型并发双 worker：** 两个编排器（或同一编排器的两轮 re-plan）可能同时看到同一个 `type+range` 未覆盖而各派一个 worker；`status --reports` / `already_covered_ranges` 都是**读**，无法阻止这个竞态。派发前必须调用引擎的原子占位：
```
secguard status --claim-type <type> --claim-range <range> --claim-holder <token> --scan-id <scan_id> --db <db_path>
# OpenCode 用 secguard_status 工具：{claim_type, claim_range, claim_holder, scan_id}
```
`--claim-holder` 是**本次派发的唯一 token**（例如 `batch-<type>-<range>-<epoch-ms>`，不需要等于宿主返回的子代理 id）；它只用于让后来者知道谁在跑。返回值：
- `{"claimed": true, "reason": "new"|"stale"|"retry"|"reclaim", ...}` → 占位成功，**同一响应轮内**立即 spawn 该批次。
- `{"claimed": false, "reason": "held", "holder": "<占用者>", "age_ms": N}` → 另一个 worker 正在跑这个 range。**不要 spawn，也不要等它**；把它当作已完成批次跳过，等它自己的完成信号回来再按 F11 吸收。
- `{"claimed": false, "reason": "done"}` → 该 range 已有结算报告（已覆盖）。跳过；只有 `needs_context` 二次下发这类**刻意重跑**才加 `--reclaim`（结果 `reason: "reclaim"`），普通恢复绝不用 `--reclaim`。
- 一个 claim 超过 30 分钟未收到结算报告即视为陈旧（dead worker）：下一次 claim 会以 `reason: "stale"` 自动接管并把 `retry_count` +1。陈旧接管不是"再等一会"的替代——F11 的"一次复核后仍无 valid 报告且无进展"仍然是重派的前提。
claim 行只是 `settlement_stats` 里的 `status='dispatched'` 占位，**不计入** `written_count`，也不进 `r_type` 样本；结算报告落盘后由 `status --reports` 吸收为 `status='done'`，该 range 随即出现在 `already_covered_ranges` 而不是 `in_flight_ranges`。**先 claim 后 spawn；claim 失败绝不 spawn。**
**多 type 批次**：一个 batch 最多含 4 个 type，每个 type 有自己的 range，因此按 `(type, range)` 逐个 claim。只有 `claimed:true` 的条目进入该 subagent 的派发提示词；`claimed:false` 的条目跳过（held = 别人在跑、done = 已覆盖），**不要**因为一个条目失败就放弃整批，也**不要**把未 claim 的 type 塞给 worker。整批都 `claimed:false` 就本轮不 spawn——但**不要结束回合**（F8）：在同一回合内继续按 F11 吸收已完成的批次（`status --reports` → `status --per-type`），然后再次尝试 claim；重复直到所有批次 done 或可 claim。

**确定性执行器开关 (F12)：** 若 `secguard config` 显示 `ai_stage_mode = "executor"`，PHASE_2 分类改由确定性进程执行——跑 `secguard classify <target> --mode executor`（灰度期先 `--dry-run` 验证接线，不开 LLM 子进程），无需本步骤的子代理派发。`ai_stage_mode` 缺省为 `agent`（本步骤的现状路径）；executor 模式的判定结果与 agent 模式同库同 `--write-json` UPSERT 路径，判定质量对齐前不得用于生产。

4. **Parallel dispatch** (ONLY when step 2 says so): first run `secguard status --reports --scan-id <scan_id>` and drop every batch already covered by a `valid:true` report, then skip every range in `status --per-type`'s `already_covered_ranges` / `in_flight_ranges` (F11a). Then validate every batch against the Batch Capacity Configuration above, claim each remaining batch with `secguard status --claim-type/--claim-range/--claim-holder` (F13), and spawn one subagent PER CLAIMED BATCH
   of types that need AI work (`candidates_by_type > 0`), the FIRST WAVE all in
   the same turn so they run concurrently (F3), then backfill the queue per F3a
   as each completion arrives:
   - Claude Code (official): the `Agent` tool (the subagent-dispatch tool; older
     versions name it `Task`). Prefer the plugin-namespaced
     `<plugin>:security-auditor` (e.g. `secguard-clang:security-auditor`) whenever
     it appears in the available-agents list; fall back to the bare
     `security-auditor` only when the namespaced one is absent. **Why:** a
     pre-plugin install left a bare-name copy at `~/.claude/agents/security-auditor.md`,
     and the bare name resolves to that copy ahead of the plugin agent — a stale
     legacy file (old `maxTurns` 30, no `Write`/`Skill` tools, no settlement
     contract) then silently caps every batch and loses the self-measured AI
     duration. Before the first dispatch, sanity-check the resolved agent:
     `maxTurns` must be ≥ 60 and its tools must include `Write` and `Skill`; if
     not, switch to the namespaced agent and continue (F10).
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
   conversation). **Dispatch-prompt budget (P0-4): keep it ≤ 400 tokens** —
   pass ONLY the incremental facts the subagent cannot derive from its own
   `agent-body.md` + the type's `SKILL.md` (both loaded by the
   `security-auditor` agent): the type name(s), per-type candidate counts, the
   candidate RANGE when split, `scan_id`, `scan_dir`, and the ABSOLUTE db + tmp
   paths. Do NOT repeat the classification rules, hint-token semantics, or the
   write contract — they live in `agent-body.md` and the skills; restating them
   per dispatch is the largest orchestrator-output cost (~25k tokens over 19
   dispatches). The template below is a reference for the RED-LINE invariants,
   not text to copy verbatim.
   ```
   RED LINE: you are a SUBAGENT. Never call `secguard report --complete-type`
   or `secguard report --audit` (the orchestrator is the single writer of
   ai_stage_status), and never re-run secguard scan/plan/index.

   Process type(s) <t1, t2, ...> ONLY. scan_id=<scan_id>, scan_dir=<output_dir>.
   (If a type is split by candidate RANGE, e.g. "null-deref #1-100", classify ONLY
   those candidates — the # column in <scan_dir>/candidates/<type>/_index.md — and
   leave the rest to sibling subagents. Echo that range as `range: "1-100"` in
   your `processed_types` block so a force-rejected call can be matched to the
   exact batch from its settlement file.)
   The scan already ran: your type's candidates are in
   <scan_dir>/candidates/<type>/_index.md and <scan_dir>/candidates/<type>/NNN_*.md
   — do NOT re-run secguard_scan or secguard_plan. The source is already embedded:
   `_index.md` has a `Source` column per candidate (the exact statement), a `Hint`
   column (the pipeline's precomputed verdict facts: `src@N`/`certain-null`/
   `maybe-null` (non-null-deref types)/`null@cfg-proof`/`null@malloc-fail`/
   `null@caller-arg`/`null@callback-entry`/`null@opaque-origin`/`null@global-null`/`null@assumed-return`/`null@external-unknown`/`array-buffer@<count-field>` (null-deref origin tier; `null@callback-entry` = function registered via function-pointer (ADDR_TAKEN) — parameter nullability bound to the registration-site context (pre-dismissed unless a `caller-null@` witness exists); `array-buffer@` = a count-gated array buffer — `count == 0 ⇒ buffer NULL/empty`, confirm when the chain dereferences it without checking the count field)/`chain-root@<fn>`+`sibling-callers@<fn1,fn2>` (the candidate's caller chain + the OTHER chains that also call the same function — a guard on a sibling chain does NOT protect this candidate)/`tainted`/`taint@none`/`weak-guard`/`divisor@<shape>`/`certain-uninit`/`maybe-uninit`/`api@`/`cat@`/`struct@<name>`/`alloc-size@<N>`/`layout-field@<name>:<off>+<size>` (layout_oob_read/write; default-ABI layout — verify packing/ABI before confirming)/`lhs@`/`rhs@`/`rhs-influenced`/`sink@`/`guard@none`/`macro-context`/`macro@<name>`/`threads@<fn>`/`write@N`/`lock@<lo>-<hi>`/`check@<fn>→use@<fn>`/`reason@<text>`/`key-size@N`/`buf@<name>`/`cap@N`/`idx@<expr>`/`src-cap@N`/`alloc@N`/`acquire@N`/`leak@definite`/`leak@conditional`/`escape@none|store|return`/`range@<interval>`/`callers@<census>`/`callsites@<census>`/`origin@<kind>`/`decl@N`/`field@<path>`/`init@none`/`init@error-path`/`init@branch`/`init@N`+`may-skip`/`expected@<type>`/`actual@<type>`/`cast@<type>`/`fmt-arg@<expr>`/`path-arg@<expr>`/`value-shape@<masked>`/`async-unsafe@<fn>`/`subject@<name>`/`count-field@<field>`/`evidence-kind@<kind>`/`sibling-guard@<fn>:<line>`/`cond@<callee>`), plus an `Evidence` column naming the exact
   candidate file, and each candidate file has a `## Code Context` block — do NOT
   issue per-candidate source READs (that is the tens-of-minutes cost). Read ONLY
   your type's `_index.md`, never the whole report.md. For a ranged batch
   (#A–#B), read the table header once and only rows #A–#B (the `#` column is
   sequential; use Read offset/limit); do NOT re-read the full table for a
   sibling range — each full read costs the same again.
   **`_index.md` sharding:** when a type's candidate table exceeds ~22500 tokens
   (90000 bytes), the scan writes it as shards `_index_1.md`, `_index_2.md`, …
   (each self-contained: title + legend + header + its candidate rows, each under
   the host's 25000-token Read cap), and `_index.md` becomes a directory page
   listing the shards + their # ranges. A subagent assigned range #A–#B SHALL
   read the shard(s) covering A–B (per the directory page's shard table), NOT the
   directory page and NOT all shards. A non-sharded `_index.md` (small type) is
   read as a single file — the directory page is only present when sharding fired.
   When a verdict needs a callee/macro/type contract that the embedded
   `## Callee Definition` / `## Macro Definition` sections do not show, use
   `secguard_def` (MCP) or `secguard def <symbol>` (Bash) — one indexed lookup,
   batch related symbols (`secguard def a b`). NEVER run a whole-repo Grep for a
   definition: it is the dominant wall-clock cost and counts as a source read.
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
       before the read (confirm from the row), `init@error-path` =
       interprocedural conditional uninit: an in-tree callee writes the storage
       only on some paths (its early return skips the write) and the caller
       discards the return — `init-writer@<callee>:<line>` names it; judge that
       error path, `init@branch` = a write exists only inside a conditional
       branch — judge that branch, `init@N`+`may-skip` = the only writes are
       loop-body-only — judge the loop condition, nothing else,
      `null@cfg-proof` = CFG-proved NULL reaches the deref (machine-proved),
      `null@malloc-fail` = proven-nullable call result (allocator / libc /
      return-NULL callee; `callee@` names an embedded body when defined in scan),
       `null@caller-arg` = unproven caller argument, `null@global-null` =
       a file-scope `static` pointer initialized to NULL and never reassigned
       (a macro body may still write it; judge the Code Context), `null@opaque-origin` =
       opaque external contract (an external caller's argument / a field value of
       an externally-defined type — fail-open assumption; a boundary scan
       pre-dismisses it unless a `caller-null@` witness exists), `null@assumed-return`
       = fail-open callee-return assumption (the callee returns a parameter /
       field / unknown call; pre-dismissed unless a `caller-null@` witness
       exists, and if it reaches you its body is embedded under
       `## Callee Definition` — judge it there), `null@external-unknown` =
       fail-open external assumption — pre-dismissed unless witnessed; otherwise
       verify or dismiss,
       `array-buffer@<count-field>` = a count-gated array buffer (`tree =
       (T *)(resp->group_data)` gated by `resp->group_num`) — `count == 0 ⇒ buffer
       NULL/empty`, so a dereference on a chain that never checks the count field
       is a real NULL dereference (confirm); dismiss only when the SAME chain
       checks the count first, and verify the count/data name pairing actually
       gates the buffer,
      `api@<name>` = the API in play, `cat@<name>` = the detector category,
      `caller-null@<why>` = the caller-null witness for a null@caller-arg row
      (names the specific caller that passes NULL / forwards an open parameter —
      check only that caller, no source read),
      `contract@known`/`contract@unknown` = unchecked-return callee contract,
      `user-contract@<symbol>` = a user-declared contract for an EXTERNAL symbol
      (secguard.toml `[contracts]`), with `takes-ownership@<param>` /
      `outparam@<param>` / `release@<mode>` carrying the declared semantics —
      judge from them, never deep-dive the unseen body,
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
      expression, `field`/`global` = struct member / module global): **EVERY
      shape — including `bare` and `field` — requires the ±8-line Code Context
      before confirming**; the shape says where the divisor comes from, NOT
      whether it is guarded (the pipeline already dropped every divisor it could
      prove non-zero, so a row that reaches you means no modelled guard exists —
      and the unmodelled ones are exactly what the window shows, e.g.
      `if (n == 0) return;`). Confirming from the `Source` column alone is how
      guarded divisions get filed as real defects. Open that candidate's
      `Evidence` file (filename in the `Evidence` column, verbatim; its
      `## Code Context` embeds the source) when the hint is insufficient to
      decide — a `certain-null` + `src@N` hint (or null-deref's `null@cfg-proof`)
      usually settles the verdict with no
      file open. A decisive hint is a verdict:
      `contract@unknown` / `macro-context` / `maybe-null` (no provable source)
      → `dismissed` from the row, citing the token; `init@error-path` and
      `taint@none` narrow the question to "is the read reachable on the
      callee's skipped-write path?" / "is the argument caller-supplied?" —
      judge that from the embedded signature/context. Only when the row has NO decisive or narrowing
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
    For each chunk: write a FRESH `<scan_dir>/../../.sgre/.tmp/<scan_id>-<claim_holder>-<type>-<range>-partN.json`
    with the Write tool (N increasing; the name carries scan_id + claim_holder +
    type + range, so two range workers of the SAME type can never collide on
    `<type>-part1.json`; if a Write returns "must read before
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
      If nothing in the range is confirmed, still write the dismissed-only
      array (every dismissed row carries `reasoning`) so the verdict ledger
      stays complete; skip the write only for a zero-candidate range.
    Report back, per type: confirmed count + the written finding ids. Dismissed
    verdicts are persisted to `candidate_verdicts` (report the dismissed count
    in `processed_types`). Emit the Structured
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
    N_type` (the adaptive per-type ceiling from Batch Capacity Configuration).
    `batch_candidate_count` is the SUM of the
   batch's per-type candidate counts. A batch that fails any ceiling SHALL be
   split (split off the heaviest type first). Do NOT read `report.md` or all
   source files yourself — each subagent reads only its own types' candidates.
5. **Collect + finalize**:

   **DB schema 速查 (列名别猜 — 猜一个不存在的列如 `f.type` 会白费 1~2 轮 `secguard schema` 往返):**
   Prefer structured tools over raw SQL — every count you need already has one:
    - per-type candidate/written → `secguard status --per-type --scan-id <id>` (`candidate_count`/`written_count`/`auto_confirmed`/`terminal_state`, no SQL). `auto_confirmed` findings are machine verdicts with `review_status` NULL until Step 5.5 reviews them; they are never dispatched to a per-candidate subagent.
    - per-type verdict split → `secguard report --audit --scan-id <id> --output-dir <dir>` returns an `audits` array (`vuln_type`/`confirmed`/`auto_confirmed`/`ai_stage_status`/`dismissed`/`unclassified`; `dismissed` = the persisted `candidate_verdicts` count, `unclassified` = `final_count − confirmed − dismissed`, the candidates nobody ever classified — it must be 0 in a complete scan). `ai_stage_status` values: `pending` (AI stage not done), `done` (AI stage complete), `failed` (AI stage failed, reserved). Sum that array for the report — do NOT raw-query `findings` to recompute it.
    **findings/ 里的 confirmed 文件 ≠ 子代理报告的 confirmed（auto-confirmed 已落库）:** `findings/<type>/NNN_*_confirmed.md` 是两类之和——(a) `auto-confirmed`：pipeline 在 scan 阶段直接机器确认的确定性发现（divide-by-zero 的 `divisor@field`/`global`、null-deref 的 `null@cfg-proof`/`null@malloc-fail`、uninit 的 certain-uninit 等），它们**不在** `candidates/_index.md` 里、子代理从来看不到；(b) 子代理写的 `confirmed`。所以 findings/ 的 confirmed 文件数可以明显大于子代理报告的数，多出的就是 auto-confirmed，**不是漏报也不是子代理说错**。最终计数一律以 `report --audit` 的 `audits` 数组（含 `auto_confirmed` 字段）为准，不要 `ls findings/` 反推、不要为这个对账。
   **DB 路径（绝对路径，否则 Exit code 1）:** every `secguard db` / `secguard schema` / `secguard report` call that takes `--db` MUST pass the ABSOLUTE path `<scan_dir>/../../.sgre/sgre.db`. A relative `.sgre/sgre.db` fails with `Error: Exit code 1` whenever your cwd is not the project root — do NOT retry it as-is; re-run with the ABSOLUTE path. **Do NOT `cd` into the scan dir to "fix" it:** commands run WITHOUT `--db` (`secguard plan`/`status`/`metrics`/`query` and `report --audit`) resolve the DB relative to cwd, so cd'ing into the scan dir would mint a second, empty `sgre.db` under the scan dir (doubling build time and splitting findings across two databases). Keep cwd at the project root for the whole run.
    **dismissed 不落 findings 表，但逐条落 candidate_verdicts 台账:** dismissed candidates write NO findings row (they never reach result.sarif/report.md), but EVERY dismissed verdict is upserted into the `candidate_verdicts` ledger — that is what `status --per-type`'s `dismissed_count` and the audit's `dismissed` column read. When `ai_stage_status='done'` for a type, the AI has processed all candidates — the `final_count − confirmed` gap is the dismissed count, which is normal, not a missing write; `unclassified = final_count − confirmed − dismissed` must be 0, and a non-zero value means candidates were never classified (a real gap, not a dismissal). **两种 dismissed 语义必须分清（C2）**：`ai_dismissed` = 子代理在分类阶段判驳的候选，**不落 `findings` 表**（无 finding 行、不参与 confirmed 计数，`written_count < candidate_count` 的差额就是它，逐条记在 `candidate_verdicts` 台账里）；`review_dismissed` = 一条 `auto-confirmed` 行在终审复核被驳回，**落库**为 `review_status='dismissed'`（`report --list --status dismissed` 能查出，`EffectiveStatus` 生效后从 confirmed 计数中剔除）。两者同名不同层，不要混用：`status --per-type` 的 `dismissed_count` 来自 `candidate_verdicts` 台账（`report --write-json` 处理 `status=dismissed` 时按 `(scan_id,vuln_type,file,line,function)` upsert，`CountCandidateVerdictsByType` 按 `vuln_type` 聚合），**反映的是 `ai_dismissed`**——`ai_dismissed` 候选不落 `findings` 表，但每条判驳裁决都落 `candidate_verdicts` 一行；`review_dismissed` 则落 `findings` 表为 `review_status='dismissed'`。`remaining = candidate_count - written_count - dismissed_count`。When `ai_stage_status='pending'` the type is in-progress (reported by `status --per-type`, not as unclassified). Because `--write-json` UPSERTs keyed on `(scan_id, rule_id, file, line, variable)`, a re-write of the same finding updates it in place: the response's `duplicates` count (and each `written[].duplicate: true`) names every idempotent update — never a second row. `function` is NOT part of the key, so a retry that omits it still updates the existing finding. Do NOT inspect the schema or raw-query `findings` to "persist" dismissed; trust `secguard status --per-type --scan-id <id>` (`written_count`/`terminal_state`/`ai_stage_status`) instead.
   If you MUST raw-query, run `secguard schema <table>` first, or use these exact names — never guess:
    - `findings`: `id, rule_id (CWE, e.g. CWE-476 — there is NO type/vuln_type column), severity, status (confirmed|auto-confirmed for new scans; legacy dismissed/suspected rows tolerated but ignored), file_path (NOT file), line_number (NOT line), function_name, variable, properties (JSON: the machine-proof basis `auto_confirm_evidence` / `auto_confirm_hint_tokens` / `auto_confirm_verdict_facts`), scan_id, review_status`
       **终报/问题表查询必须过滤 `review_status`:** an auto-confirmed finding
       carries `review_status` NULL at scan (first-pass verdict only) and awaits Step 5.5's review. If a
       later pass ever downgrades one to `dismissed`, a raw `SELECT ... FROM
       findings` would still count it as present, so any final-total query must
       add `AND (review_status IS NULL OR review_status NOT IN ('dismissed'))` —
       or use `report --list --status confirmed` (which applies `EffectiveStatus`)
       instead of raw SQL.
    - `scan_stats`: `scan_id, vuln_type (kebab-case type name), seed_count, final_count, ai_stage_status (pending|done|failed)`

   **唯一权威口径 (F5a) — DB / 结算文件 / audit summary 不许混用：** 三者分工固定，聚合时只认一个来源：
   - **落库发现** → `findings` 表（`report --list` / `report --audit` 只投影它）。`--write-json` 按 `(scan_id, rule_id, file, line, variable)` 幂等 UPSERT；重复写会返回 `duplicates`，不是新增行。
   - **每类型进度/覆盖** → `secguard status --per-type`（引擎从 DB 计算 `terminal_state` / `already_covered_ranges` / `in_flight_ranges`）。
   - **结算文件** → `.sgre/.tmp/<subagent_id>[-<type>][-chunk-<k>]-report.json` 只是**完成信号/传输记录**。唯一受支持的读取入口是 `secguard status --reports`（按 `subagent_id`+type+range 去重、valid 优先、retry 覆盖同一文件名）。**绝不 glob 聚合 `*.json`**：`-report.json`、per-type checkpoint 与 chunk 会重复计数同一批次（生产曾把 implicit-contract 的 665 条聚合成 934 条）。
   - **全轮汇总** → 只认 `report --audit` 的 `summary`（`report.md` / `audit-report.md` 是它的同源渲染）。不要相加 `audits`、不要 `ls findings/` 反推。

   **上报解析与 DB 二次校验 (F5):** For each subagent result, parse by `format_version`
   to know which types it was ASSIGNED, which it reports as FINISHED
   (`processed_types`), and which it reports as ABANDONED (`failed_types`, with a
    `reason`). Do NOT trust the self-reported `reason` or counts — the LLM
    misreports (e.g. a Bash-permission misjudgment reported as
    `api-quota-exhausted`, or dismissed candidates counted into `written`). The DB
    is the SOLE authority for "did data land"; the subagent's processed/failed
    split is the only signal for "did it FINISH", because **dismissed verdicts
    live in `candidate_verdicts`, not in `findings` — `written_count <
    candidate_count` is NORMAL whenever anything was dismissed, never a missing
    write by itself (check `dismissed_count` and `remaining`/`uncovered_ranges`
    for the real gap).** For EVERY assigned
   type, run `secguard status --per-type --scan-id <scan_id>` and decide by
   `terminal_state` (the authoritative signal) + `candidate_count` + `written_count`
   (NOT the raw `findings` count, which cannot tell "no candidates" from
   "candidates but never written"):
   - `candidate_count == 0` → the type had nothing to classify → `done` (success), NEVER failed.
    - Subagent reports the type FINISHED (`processed_types`) → run `--complete-type`
      for it FIRST (the orchestrator's step, below), then re-read `terminal_state`:
      `done` = full success — the `candidate_count − written_count` gap is the
      DISMISSED count (normal, persisted to `candidate_verdicts`). NEVER judge
      this PARTIAL. If `--complete-type` returns `status:"incomplete"`, the type
      is NOT actually finished: re-dispatch exactly the returned
      `uncovered_ranges` (a sibling range is still running or was lost), then
      retry after those settle — do NOT force it done.
    - Subagent reports the type ABANDONED (`failed_types`), or never reports it
      finished → decide by DB `written_count`:
        - `written_count == 0` → FAILED with `reason: "empty-output"` (data did NOT
          land), regardless of the subagent's self-reported reason.
        - `written_count > 0` → PARTIAL (context-overflow): the uncovered
          candidates were never written. Re-dispatch exactly the
          `uncovered_ranges` from `status --per-type` as smaller batches (per
          the adaptive capacity ceiling, NEVER a full-range retry) until
          `uncovered_ranges` is empty or the retry budget (3 rounds) is
          exhausted; only then mark `missing-type` and surface the residual gap
          in the 观察项表.

   **失败降级决策 (F1):** For each FAILED type (`candidate_count > 0 && written_count == 0`):
   - **Recover by re-dispatch first, not by sequential self-classification.** A `written_count == 0` type was almost always NEVER STARTED (a sibling type overflowed the subagent's context before it was reached), so its candidates are untouched. Dispatch ONE fresh single-type subagent per leftover type (single type, FULL candidate range) in a single turn — claim each one first per F13 and spawn only on `claimed:true`; a fresh subagent has a full context window and will not overflow — then re-run the F5 DB check for that type before proceeding. **Do NOT fall back to classifying the leftover types yourself in sequence** — that serial loop is the 3–5-minute wall-clock cost this rule removes. (Guard: a type whose `terminal_state` is already `done` but `written_count == 0` means "all candidates dismissed", which is SUCCESS, not a leftover — do not re-dispatch it.)
    - Only when a subagent is unavailable (parallel dispatch cannot run) OR the re-dispatched subagent AGAIN lands `written_count == 0`, mark the type `missing-type` with the DB-derived `reason` and CONTINUE. A `0 < written_count < candidate_count` type (mid-type `context-overflow`) is re-dispatched by `uncovered_ranges` (see F5 above), never by FULL candidate range.
    - The orchestrator SHALL NOT run `report --audit` while ANY type still has `candidate_count > 0 && written_count == 0` and is not yet marked `missing-type` — the engine now HARD-GATES this: `report --audit` refuses (exit 1, `status:"incomplete"`) whenever any type with candidates has `ai_stage_status != "done"`. After marking the residual types `missing-type` (post retry-budget), run the audit as `report --audit --allow-partial ...` so the partial artifacts are explicitly labelled PARTIAL, and list every missing-type in the 观察项表. Never present a --allow-partial report as a complete scan.
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
    - Repo-wide Grep (wall-clock): a whole-tree `Grep` for a definition
      (`**/*.{c,h}` or an absolute source root) is the dominant production
      wall-clock cost. It is NOT a legitimate substitute for `secguard def`: the
      transcript should show `secguard def <symbol>` (or an embedded
      `## Callee Definition`), not repeated whole-repo
      greps. Surface a type with >1 repo-wide Grep as "全仓 grep 违规（应改用
      secguard def）" in the 观察项表; re-dispatch that type ONCE with the def
      instruction rather than letting it grep again.
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
    not re-dispatch for it; note it and move on. The structured report also carries
    `repo_greps`: a type with `repo_greps > 1` is a 读源违规 even when
    `source_reads` is within budget (a whole-repo Grep is not an Evidence open).
    On a transcript-less host, trust `repo_greps` over the absence of a visible
    Grep call; re-dispatch that type ONCE with the `secguard_def` instruction.

    **`needs_context` 二次下发:** if a subagent reports `needs_context`, the
    orchestrator re-dispatches EXACTLY those candidate `#`s ONCE (one subagent,
    same type, explicit "open the Evidence files, then the ≤5 source reads,
    before you may write dismissed"), then re-runs the F5 DB check for that type.
    The range is already `done`, so this deliberate re-review must claim with
    `--reclaim` (F13); a plain claim returns `claimed:false, reason:"done"` and
    must NOT be bypassed by spawning anyway. Do not re-dispatch a whole type for a
    handful of `needs_context` entries and do not silently drop them — a dropped
    entry is an unclassified candidate.

    **`needs_context` / dismissed 外显 (R1) — 人工复核召回台账:** 二次下发完成后，
    把每个子代理落盘的 `.tmp/<subagent_id>-report.json`（O2 已要求写入）里的
    `needs_context`（candidate `#` + 一行理由）与 `dismissed` 计数按类型聚合，写一份
    `<scan_dir>/ai-dismissed.json`（每类型：`dismissed` 计数 + 仍悬而未决的
    `needs_context` 条目）。二次下发后仍悬置的 `needs_context` 条目**必须**在最终报告
    观察项表里占一行 `| <type> | 待人工复核 N 条：<candidate#s> |`，不得静默吞掉。
    这份台账是给客户的人工复核召回面——被驳回 / 未判定的候选绝不能只存在于子代理的
    聊天消息里。

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
    (with `review_status` NULL) straight into `findings`, so they are NOT
    in `candidates/_index.md` and the audit would ship them unexamined. Do NOT conflate two
    different things: (1) auto-confirmed rows are **not dispatched** to any
    security-auditor subagent and add nothing to the batch budget; (2) the
    **orchestrator still runs Step 5.5 on them itself** — a bounded, ONCE pass,
    not a per-candidate re-review. Skipping 5.5 is a process-completion failure,
    not a valid "already reviewed" shortcut. A
    machine proof is only as good as its premise, and production measured a 75%
    false-positive rate on the `uninit` tier (macro for-init writes, block-scope
    `extern` declarations, output-parameter fills). Step 5.5 below is the
    bounded verification pass for exactly those rows; it lists them via
    `report --list-auto-confirmed` (or `status --per-type` unreviewed) and writes
    verdicts with `--review-json` — NOT the removed
    per-candidate re-review loop (no re-derivation of every proof). The final free-form judgment is
    still done by the SAME AI agent (the security-auditor subagent's own LLM) as
    it classifies candidates — there is NO separate or customer-configured LLM
    anywhere in the pipeline.

    After ALL subagents (or your sequential loop) are done, run the **baseline audit**: `secguard report --audit --scan-id <scan_id> --output-dir <output_dir>`
   ONCE to regenerate `report.md` (verdict-stage, confirmed only) + `result.sarif`
   + `findings/`. The engine self-measures the AI-classification wall-clock from
   the settlement reports' timestamps, persists it to `scan_runs.ai_duration_ms`
   (source `self-measured`) and renders total + per-type timing in
   `audit-report.md`; do NOT pass `--ai-duration-ms` unless the host cannot write
   settlement files (it is an override, not a required input). Verify
   `<output_dir>/result.sarif` is non-empty and `findings/` has files; if not, a
   write did not land — find the `per_finding_warning` and fix it.

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
      | CWE-457 uninit | `certain-uninit` / `init@none` = "never written" | the variable is written by a macro (`macro-context` in its hints, or its name appears in a macro invocation in the window), is a block-scope `extern`/`static`, the struct is written field-by-field before the read. A row whose hints carry `init@branch`/`init@error-path` contradicts the `init@none` premise → dismiss citing the token. A row passed as `&var` to an IN-SCAN callee is dismissed only when that callee's body writes `*var` (cite file:line); a callee outside the scan stays `unverified` |
      | CWE-476 null-deref | `null@cfg-proof` = "NULL reaches on every path" | the dereference sits in a macro that may assign the pointer (an iteration macro's loop header) |
      | CWE-134 format-string | a non-literal format reaches a sink | every in-tree caller of the format parameter passes a literal (`callsites@N:all-literal`) |
      | CWE-369 divide-by-zero | a proved-zero / non-zero-constant divisor | a zero guard sits in the ±8-line window before the division |
      | other | the proof class named in the row's facts | a concrete `file:line` in the source contradicts the premise |

   c. Write the dismissals in ONE batch (no per-row subprocess), every reason citing
      a `file:line` fact: `secguard report --review-json <file.json> --db <abs db>`
      with `[{"id":<id>,"review_status":"dismissed","review_reasoning":"<file:line +
      why-safe>"}]`. Rows you keep ALSO need a write — batch them as
      `[{"id":<id>,"review_status":"confirmed","review_reasoning":"<premise holds>"}]`
      in the same `--review-json` call (or a second one), so the
      `unreviewed_auto_confirmed` warning clears and `result.sarif` is final. On
      OpenCode, write the same batch through the `secguard_review` tool's `reviews`
      param (it wraps `--review-json`); list the rows through its
      `list_auto_confirmed` param (the auto-confirmed rows carry `review_status`
      NULL until this step, so the listing returns exactly the unreviewed set) or
      with the `secguard_db` raw SQL of step a.
   d. Run the **final audit** ONCE so `result.sarif` / `report.md` / `findings/` reflect the
      dismissals — the regenerated `result.sarif` is the deliverable. Do not pass
       `--ai-duration-ms`: the self-measured AI stage comes from the settlement
       files, and Step 5.5 runs after them, so its time is orchestrator overhead —
       note "5.5 耗时计入编排开销" in the observations table. Pass the flag ONLY
       as an override on a host that cannot write settlement files.
   e. Budget: bounded. With more than ~40 machine findings, verify the
      assignment-based premises first (CWE-457 / CWE-476) and record the remainder as
      "machine verdicts unverified" in the report's limitations. Never read source for
      a row the checklist above settles from the row itself.
   f. **Failure downgrade:** a 5.5 sub-step failure (SQL error, `--review-json`
       reject, audit failure) does NOT block Step 6 — add one observations-table
       row `| 5.5 | 机器判定终审未完成：<failed sub-step/reason>；result.sarif 含未复核 auto-confirmed |`
       and continue. Omit the row when 5.5 completes.

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
   c. Classify every candidate. **容量纪律（与 full scan 同一调度器）：该类型 `candidate_count > 20` 时禁止在主上下文逐候选串行分类——按 Batch Capacity Configuration 的 `N_type` 切 range、按 F13 claim、派子代理处理（filtered 与 full scan 共用同一 range 调度）；`candidate_count ≤ 20` 才允许本循环的顺序快路径。**
   d. Cross-reference: ≤5 source-read turns, absolute paths from the candidate
      Location block.
    e. **WRITE now**: `secguard_report` with `findings` for THIS type, passing
      `scan_id` + `output_dir` AND `finalize: false`（每次写入都不得触发逐类型 full audit；终态渲染只在全部类型完成后统一一次 `report --audit`，含 Step 5.5 auto-confirmed review 与 complete-type 派生）。 Every candidate gets a verdict (confirmed /
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
