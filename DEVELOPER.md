# DEVELOPER.md — SecGuard-Clang Developer Guide

This is the developer-facing companion to `CLAUDE.md` (which documents the
architecture and build) and `docs/` (which holds the design history). This file
is the **operator's manual**: the state machine, the layer ownership map, and
the playbooks for locating a specific problem in a specific layer.

> **One-line mental model:** Source → **A1 indexer** → **A2 semantic graph** →
> **A3 detectors** (emit `security_events`) → **A4 planner** (converge + rank) →
> **AI agent first pass** (`findings.status`) → **A5 second-round review**
> (`findings.review_status`) → developer-facing `audit-report.md`.

---

## 1. The State Machine (READ THIS FIRST)

There are **four distinct "status" concepts**, and confusing them is the #1 way
to misdiagnose a finding. They live in different layers, are written by
different actors, and are stored in different places.

| # | Name | Values | Who writes it | Persisted? | Meaning |
|---|------|--------|---------------|-----------|---------|
| ① | `suspicion_level` | `confirmed` / `suspected` / `possible` | **planner** (A4) | No (JSON only) | The pipeline's *prior*: how certain the graph is **before** the AI looks |
| ② | `findings.status` | `open` / `confirmed` / `suspected` / `dismissed` | **AI agent** (first pass) | Yes (`findings` table) | The AI's first-pass classification |
| ③ | `findings.review_status` | `confirmed` / `dismissed` / `suspected-kept` (or `''`/NULL) | **AI agent** (A5 second pass) | Yes (`findings` table) | The second-round verdict over `suspected` only |
| ④ | `effectiveStatus()` | `confirmed` / `suspected` / `dismissed` | **report.go** (derived) | No (computed) | The final developer-facing verdict |

They are deliberately **different words for different phases**, not synonyms.
A candidate can be `suspicion_level=possible`, classified `status=suspected`,
then reviewed `review_status=confirmed` — three fields, three phases, three
different owners.

### 1.1 `suspicion_level` — the A1–A4 prior (who: planner)

Set in `internal/planner/planner.go` `seedCandidatesByType()`, seeded from the
`VulnTypeSpec` and then refined by flow filters.

| Value | Meaning | Set by | Example |
|-------|---------|--------|---------|
| `confirmed` | The detector/flow **proved** the defect on the graph | `DefaultSuspicion` / `CategoryConfidence`, or a flow filter upgraded it | null source reaches deref; constant index overruns array; freed state reaches use |
| `suspected` | A heuristic recognized the pattern but the graph **could not** prove it | `DefaultSuspicion` (default) | unguarded `strcpy`; weak PRNG; data race |
| `possible` | Only theoretical — needs an operand to reach an extreme value | `CategoryConfidence` | `malloc(n+1)` with caller-influenced `n`; unsigned wraparound inside a bounds check |

**Where each value comes from (grep targets):**

- `internal/planner/registry.go` — `DefaultSuspicion` (type-level default) and
  `CategoryConfidence` (per-event-category override, "detector proved it").
- Flow filters that **upgrade to `confirmed`** when the graph proves the pattern:
  - `filter_nullable_source.go` (null-deref)
  - `filter_lifetime.go` (use-after-free)
  - `filter_double_free.go` (double-free)
  - `filter_uninit_flow.go` (uninit)
  - `filter_taint_source.go` (injection / path-traversal / format-string)

`suspicion_level` is **not a DB column** — it travels in the `EvidenceItem`
JSON as `suspicion_level`, is used by `ranker.go` to order candidates
(`confirmed`=1.0, `suspected`=0.7, `possible`=0.5), and tells the AI agent how
much depth to spend (see `agent-body.md` "Pipeline Confidence Tiers").

### 1.2 `findings.status` — the AI first pass (who: AI agent)

Persisted in the `findings` table (`internal/db/schema.go`). The AI agent
writes it via `secguard report --write` (one value per candidate).

| Value | Meaning | Developer should see it? |
|-------|---------|--------------------------|
| `open` | Default, unclassified — a sign the agent never classified this candidate | **No** — process gap |
| `confirmed` | The AI verified a real vulnerability | Yes — fix it |
| `suspected` | Needs human judgment (partial validation, external input, short read) | Yes — triage it |
| `dismissed` | False positive, with a one-line `evidence` why | No — but the reason is auditable |

### 1.3 `findings.review_status` — the A5 second round (who: AI agent)

Persisted in the `findings` table. The AI agent runs this **only over findings
it wrote as `status=suspected`**, via `secguard report --review --id=<id>
--review-status=... --review-reasoning=...`.

| Value | Meaning | Result |
|-------|---------|--------|
| `confirmed` | Second look: it is real | promoted out of suspected |
| `dismissed` | Second look: it is a false positive | dropped |
| `suspected-kept` | Genuinely uncertain (external input w/o provable bound, partial blacklist, short read may be OK) | stays suspected |
| `''` / NULL | Never reviewed | keep first-pass `status` |

### 1.4 `effectiveStatus()` — the derived final verdict (who: report.go)

Defined in `internal/cli/report.go`. This is the single source of truth for the
developer-facing counts in `audit-report.md`:

```
review_status == "confirmed"      → confirmed
review_status == "dismissed"      → dismissed
review_status == "suspected-kept" → suspected
review_status == "" / NULL        → status (first-pass value)
```

**Rule of thumb:** a `suspected` finding that survives A5 must be a genuine
"needs human judgment" case. If it is deterministic (weak algorithm, constant
SQL, guarded division, checked allocation), the pipeline or the first pass
missed evidence — the fix belongs in the detector/planner, not in A5.

### 1.5 The full lifecycle (visual)

```
security_events (A3)                       [detector emits evidence]
   ↓ seed
Candidate ──suspicion_level = DefaultSuspicion / CategoryConfidence── [A4 seed]
   ↓ flow filters may upgrade → confirmed / drop with Dismissed reason [A4 converge]
   ↓ ranker (confirmed 1.0 / suspected 0.7 / possible 0.5)            [A4 rank]
EvidenceItem (JSON, carries suspicion_level)
   ↓ AI agent first pass
findings.status = confirmed | suspected | dismissed                   [A4 classify]
   ↓ AI agent second pass (only over suspected)
findings.review_status = confirmed | dismissed | suspected-kept       [A5 review]
   ↓ report.go
effectiveStatus() → confirmed | suspected | dismissed                 [final]
   ↓ markdown.go statusSuffix
per-finding file renamed `_c` / `_s` / `_x`
```

The per-finding filename suffix (`internal/report/markdown.go` `statusSuffix`)
maps the **final** status: `confirmed→_c`, `suspected→_s`, `dismissed→_x`.

---

## 2. Layer Ownership Map (who owns which table)

The DB is `sgre.db` (SQLite, 4 layers + 2 support tables). Each table has
exactly one **writer** and one primary **reader**. If you're chasing a bug,
start at the table, find its writer, and read that file.

| Layer | Table | Writer (package/file) | Reader | Purpose |
|-------|-------|-----------------------|--------|---------|
| L1 | `files` `functions` `variables` `expressions` `types` `locations` | `internal/indexer` | graph, detectors, planner | stable program facts |
| L2 | `graph_nodes` `graph_edges` | `internal/graph` | planner flow filters | call/data-flow/ownership/CFG |
| L3 | `security_events` | `internal/evidence` (22 detectors) | planner seed | raw security evidence |
| L4 | `findings` | AI agent (via `cli/report.go`) | developer, report | final verdicts + A5 |
| — | `scan_stats` | planner (per scan/vuln) | audit-report | seed→final convergence metrics |
| — | `function_summary` | `internal/evidence/null_source.go` (only null-deref today) | agent | cross-function contracts |

**Design invariants (do not break):**

- Tables are organized by **program fact type**, never by vulnerability type.
- Skills are **query consumers only** — they never create tables.
- The AI agent must never read `security_events` to recover filtered-out raw
  candidates (enforced by `agent-body.md` "Pipeline boundary").
- `planner.VulnTypeSpec.CWE` is the single source of truth for CWE↔type mapping
  — never hardcode a parallel map in `report/`, `db/`, or `cli/`.

---

## 3. Playbooks — locate a specific problem in a specific layer

### 3.1 "Too many `suspected` findings" (the recurring complaint)

This almost always means **A4 did not converge the type**, so the AI is being
asked to prove/refute what the graph should have already decided.

Check, in order:

1. **Is the type on the `default` filter chain?**
   `internal/planner/planner.go` → `getFilters()`. The `default` branch is only
   `CallReachFilter` + `SafeFunctionFilter` — it does reachability + whitelist,
   **no semantic confirmation**. Any type there will flood A5 with `suspected`.
   → The fix is a new filter (or a `CategoryConfidence` map), not more AI.
2. **Does the detector's `CategoryConfidence` mark provable categories as
   `confirmed`?** See `registry.go`. Compare `buffer-overflow` (has the map)
   with a type missing it. `crypto-misuse` weak algorithms are *provably broken*
   — they must be `confirmed`, never `suspected`.
3. **Is the detector over-approximating a deterministic "safe" case?**
   e.g. `injection.go` used to flag every `sqlite3_exec` including constant SQL.
   A literal SQL string cannot be injection — suppress it in the detector, don't
   ship it to the AI.
4. **Measure before/after:** `secguard db "SELECT vuln_type, seed_count,
   final_count FROM scan_stats ORDER BY final_count DESC"` — a large `final`
   (post-filter) count for a type means the filters aren't pruning. The
   `audit-report.md` "Filter Efficiency" column shows this per type.

**Root-cause locations:** `planner/registry.go` (confidence), `planner/planner.go`
(`getFilters`), `planner/filter_*.go` (per-type filters), `evidence/*.go`
(detector precision), `planner/null_flow.go` (the reusable flow engine — reuse
it instead of ad-hoc regex).

### 3.2 "Missing a real vulnerability" (false negative)

1. **Did the detector even emit the event?** `secguard db "SELECT event_type,
   COUNT(*) FROM security_events GROUP BY event_type"`. If the event type is
   missing/zero for that code, the detector (`internal/evidence/<type>.go`) is
   the culprit.
2. **Was it dropped by a filter?** Re-run `secguard plan <type>` and inspect the
   JSON `summary.dropped` / `dropped_by_reason` — every drop has a filter name +
   reason. That tells you exactly which filter over-pruned.
3. **Was it whitelisted?** `internal/apikb/apikb.go` `SafeFunctions` /
   `SafeWrappers` — a name wrongly listed there silently drops findings.

### 3.3 "Reported but not real" (false positive)

1. **Detector over-approximation** → tighten the detector (constant detection,
   guard detection), as §3.1 step 3.
2. **Missing semantic suppression** → add a filter that drops the provably-safe
   pattern (guarded, bounded, transferred ownership). See the null-deref 7-filter
   chain as the reference design.
3. **AI misclassification** → the finding's `evidence` / `review_reasoning` is
   the audit trail; read the per-finding `<vuln-type>/NNN_*_x.md` file.

### 3.4 "Status seems wrong in the report"

- Developer report says `suspected` but you expected `confirmed` → check
  `findings.review_status`; if it's `''`/NULL, the A5 pass never ran (agent
  missed the second-round step — see §4.2).
- Counts don't match your expectation → confirm `report.go` uses
  `effectiveStatus()` (it does; §1.4). If a finding was reviewed `confirmed`,
  it counts as confirmed, not suspected.

---

## 4. Adding / wiring a vulnerability type (end-to-end)

Adding a type touches **four** places, in this order. The CWE comes for free
from `VulnTypeSpec.CWE` — never hardcode a parallel CWE map.

1. **Detector** — `internal/evidence/<type>.go`. Implement `Detector`, emit
   `security_events` rows with `event_type` + `properties` JSON, then
   `RegisterDetector` in `internal/evidence/registry.go`.
2. **Planner spec** — `internal/planner/registry.go`. `RegisterVulnType` with
   `Name`, `CWE`, `SeedEventType`, `DefaultSuspicion`, `FilterChain`, and
   `CategoryConfidence` for any category the detector *proves*.
3. **Filter chain** — `internal/planner/planner.go` `getFilters()`. Wire a
   `FilterChain` name to the filters. **Do not leave it on `default` unless the
   type genuinely has no graph signal** — that's how you get suspected floods.
4. **Agent skill** — `extension/shared/skills/<type>/SKILL.md`. Give the AI the
   classification rules (which evidence → confirmed/suspected/false-positive).

Then `extension/shared/agent-body.md` + `command-instructions.md` carry the
workflow; the type is auto-discovered via `secguard types` (never hardcoded).

### 4.2 Wiring the A5 second round (already done, here for reference)

The A5 flow is three coordinated pieces — change all three together:

1. **DB**: `findings.review_status` / `review_reasoning` columns
   (`internal/db/schema.go`), `UpdateFindingReview` + `GetFindingByID`
   (`internal/db/crud_findings.go`).
2. **CLI**: `secguard report --review --id --review-status --review-reasoning`
   (`internal/cli/report.go`), plus `effectiveStatus()` for the final counts.
3. **Agent**: `extension/shared/agent-body.md` ("Second-Round Confirmation")
   + `command-instructions.md`, and the OpenCode `secguard_report.ts` tool
   (returns `written[].id`, accepts a `reviews[]` batch).

---

## 5. Build & test quick reference

```bash
cd sgre
go build -buildvcs=false ./...
go test -buildvcs=false ./...                                  # full suite (SQLite + tree-sitter)
go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/
```

If the default `GOCACHE` is not writable: `GOCACHE=$PWD/.tmpcache
TMPDIR=$PWD/.tmpcache` (`.tmpcache` is gitignored).

Test fixtures live in `sgre/testdata/tc*.c`; each detector has a matching test
in `internal/evidence/*_test.go`. When you add a suppression/filter, add a
fixture that proves the new *safe* case produces **zero** events and the
*unsafe* case still produces one — that's the regression guard.

---

## 6. Where each "concept" lives (quick grep map)

| Concept | File |
|---------|------|
| `suspicion_level` seed | `planner/planner.go` (`seedCandidatesByType`) |
| `suspicion_level` upgrade | `planner/filter_nullable_source.go`, `filter_lifetime.go`, `filter_double_free.go`, `filter_uninit_flow.go`, `filter_taint_source.go` |
| ranker weights | `planner/ranker.go` (`confidenceValue`) |
| `CategoryConfidence` / `DefaultSuspicion` | `planner/registry.go` |
| filter chain assembly | `planner/planner.go` (`getFilters`) |
| `findings` schema (status/review_status CHECK) | `db/schema.go` |
| `--write` / `--review` / `effectiveStatus` | `cli/report.go` |
| `_c/_s/_x` filename suffix | `report/markdown.go` (`statusSuffix`) |
| reusable flow engine | `planner/null_flow.go` (`flowAnalyzer`) |
| safe API/wrapper whitelist | `apikb/apikb.go` |
| agent first-pass rules | `extension/shared/agent-body.md` ("Classification Rules") |
| agent A5 rules | `extension/shared/agent-body.md` ("Second-Round Confirmation") |
