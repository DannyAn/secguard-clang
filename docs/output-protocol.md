# SecGuard Output Protocol

## Overview

SecGuard scan results are written to a structured directory under `.codeagent/secguard-clang/`. Each scan produces a uniquely-identified directory containing SARIF 2.1 output, a human-readable Markdown report, and two Markdown trees grouped by vulnerability type. The SQLite database is stored at `.codeagent/secguard-clang/.sgre/sgre.db` (sibling of `scans/`).

**Two trees, two audiences** — this separation is a contract, not a convention:

| Directory | Written by | Contains | Filename |
|-----------|-----------|----------|----------|
| `candidates/<vuln-type>/` | the scan (convergence pipeline) | every converged candidate — unclassified leads, **not** defects | `NNN_<file>_<line>.md` |
| `findings/<vuln-type>/` | the AI's persisted verdicts | **only** actionable verdicts: confirmed + suspected | `NNN_<file>_<line>_<confirmed\|suspected>.md` |

A **dismissed** (false-positive) verdict produces **no file** under `findings/`: it is recorded in the `findings` table and annotated onto the matching `candidates/` file (`- **AI Verdict:** dismissed` plus an `## AI Verdict` section carrying the reason). This keeps the review surface equal to the work a developer actually has to do, while the exclusion stays auditable. `secguard report --audit --output-dir <scan-dir>` re-derives `findings/` from the database, so unclassified or dismissed leftovers can never accumulate there.

## Directory Structure

```
<project-root>/
├── .codeagent/
│   └── secguard-clang/
│       ├── .sgre/
│       │   └── sgre.db                 # SQLite database (program graph + findings)
│       └── scans/
│           ├── latest -> 2026-08-11_143022_a1b2   # symlink to most recent scan
│           ├── latest.txt                          # fallback on symlink-unsupported FS
│           ├── 2026-08-09_202844_a3f2/             # historical scan (preserved)
│           │   ├── candidates.sarif    # SARIF 2.1, candidate stage (level note)
│           │   ├── result.sarif        # SARIF 2.1, verdict stage (after classification)
│           │   ├── report.md           # Human-readable summary
│           │   ├── audit-report.md     # Per-skill pipeline + AI statistics
│           │   ├── dismissed.json      # Ledger of pipeline-dropped candidates
│           │   ├── scan.log            # NDJSON runtime log for this scan
│           │   ├── candidates/         # pipeline evidence, grouped by vuln type
│           │   │   ├── buffer-overflow/
│           │   │   │   ├── 001_allocator_c_31.md
│           │   │   │   ├── 002_parser_c_87.md
│           │   │   │   └── ...
│           │   │   └── null-deref/
│           │   │       └── 001_main_c_42.md
│           │   └── findings/           # AI verdicts only (confirmed/suspected)
│           │       ├── buffer-overflow/
│           │       │   └── 001_allocator_c_31_confirmed.md
│           │       └── null-deref/
│           │           └── 001_main_c_42_suspected.md
│           └── 2026-08-11_143022_a1b2/             # most recent scan
│               ├── candidates.sarif
│               ├── result.sarif
│               ├── report.md
│               ├── scan.log
│               ├── candidates/
│               └── findings/
```

`findings/` does not exist until the AI persists its first actionable verdict for
the scan, and a vuln-type subdirectory disappears again when none of its
candidates survives classification.

## Scan ID Format

The scan ID is a timestamp plus a 6-character cryptographically random hexadecimal suffix: `YYYY-MM-DD_HHMMSS_<6-hex>` (e.g., `2026-08-09_202844_a3f2b1`). The timestamp prefix preserves human-readability (when the scan ran) and lexicographic sortability (scans sort chronologically by directory name). The 6-char hex suffix provides 16,777,216 possible values per second, making same-second collisions negligible. Generated using `crypto/rand` (Go) or `crypto.randomBytes` (TypeScript/Node).

## Scan Artifact Retention

All scan directories under `scans/` are preserved indefinitely across scan rounds. Running a new scan does NOT delete, overwrite, or modify any files in previously-created `scans/<scan_id>/` directories. There is no automatic rotation or cleanup policy; cleanup is the user's responsibility (out of scope for this feature).

The `security_events` SQLite table is a transient detector working table, cleared via `DELETE FROM security_events` at the start of each scan round. This DB clear does NOT affect filesystem scan artifacts or per-scan log files. The `findings` and `scan_stats` tables accumulate across scans, tagged by `scan_id`.

## Latest Symlink

After each scan completes and all artifacts are written, a `latest` symlink is atomically created or updated in `scans/`:

- **Path**: `scans/latest` → `scans/<scan_id>` (most recent completed scan)
- **Target**: Relative (the scan_id directory name only, e.g., `2026-08-11_143022_a1b2`), so the project root remains relocatable.
- **Atomic update**: A temp symlink `scans/.latest.tmp.<pid>` is created first, then `rename(2)` atomically replaces `scans/latest`. This ensures no window exists where `latest` is absent or broken, even under concurrent reads.
- **Fallback**: On filesystems that do not support symbolic links (e.g., Windows without developer mode), a regular file `scans/latest.txt` is created containing the scan_id string. The `latest` symlink and `latest.txt` are mutually exclusive.
- **Non-fatal**: If the symlink update fails, the scan still succeeds. A warning is emitted to stderr.
- **Consumer usage**:
  - POSIX: `cat scans/latest/report.md` or `cat scans/latest/result.sarif`
  - Windows fallback: Read `scans/latest.txt` to get the scan_id, then access `scans/<scan_id>/report.md`

## File Formats

### candidates.sarif (candidate stage) vs. result.sarif (verdict stage)

SARIF (Static Analysis Results Interchange Format) 2.1 is emitted in **two
separate files**, one per stage — never one file overwritten in place:

| File | Written by | Results | Level |
|------|-----------|---------|-------|
| `candidates.sarif` | `secguard scan` | every converged candidate, unclassified | always `note` (informational) |
| `result.sarif` | `secguard report --audit` | AI-classified findings only (dismissed excluded) | `error` = confirmed, `warning` = suspected |

`result.sarif` **does not exist until the AI classification is persisted**. That
is deliberate: a CI gate or IDE pointed at `result.sarif` can then never mistake
the pre-convergence candidate set for defects, which is the entire point of the
convergence pipeline. Consumers that do want the raw leads read
`candidates.sarif` and get honest `note`-level results, with the pipeline prior
in `properties.suspicion_level` (a classifier effort budget, not a severity).
Both files carry `runs[0].properties.stage` (`candidates` / `findings`).

`result.sarif` contains:
- `$schema`: `https://json.schemastore.org/sarif-2.1.0.json`
- `version`: `2.1.0`
- `runs[0].tool.driver.name`: `secguard-clang`
- `runs[0].properties.stage`: `findings` (the candidate-stage file carries `candidates`)
- `runs[0].results[]`: One entry per confirmed/suspected finding (dismissed excluded) with:
  - `ruleId` (CWE), `level` (`error`=confirmed / `warning`=suspected)
  - `message.text` — the finding summary (fallback to reasoning → evidence)
  - `properties.reasoning` / `properties.exception_check` — the structured "why"
  - `fixes[].description.text` — the concrete fix strategy (often a code snippet)
  - `locations[]` with artifact URI, `region` (line + `snippet` of that line) and `contextRegion` (the ±`--context-lines` window with its `snippet`), so a viewer can render the code without the source tree

Vulnerability type to CWE mapping:
| Vuln Type | CWE |
|-----------|-----|
| null-deref | CWE-476 |
| buffer-overflow | CWE-787 |
| memory-leak | CWE-401 |
| injection | CWE-78 |
| resource-leak | CWE-404 |
| uninit | CWE-457 |
| use-after-free | CWE-416 |
| double-free | CWE-415 |
| format-string | CWE-134 |
| integer-overflow | CWE-190 |
| race-condition | CWE-362 |
| hardcoded-secret | CWE-798 |
| deadlock | CWE-667 |
| crypto-misuse | CWE-327 |
| out-of-bounds | CWE-125 |

### report.md

Human-readable summary with:
- Header with scan timestamp and target path
- Summary table: vulnerability type, count, severity breakdown
- Findings table: # | Type | Severity | Confidence | Location | Variable | Status
- Paths to both SARIF stages, the `candidates/` evidence directory, and the `findings/` verdict directory

The summary header reports both `Functions indexed` (functions parsed during
this run; unchanged files are skipped, so a re-scan reports 0) and
`Functions in index` (total functions available in the program graph for the
current repository).

### Candidate evidence (`candidates/<vuln-type>/NNN_<file>_<line>.md`)

Written at scan time, one file per converged candidate:
- A banner stating this is candidate evidence, not a defect or a verdict
- **Location**: file:line, function, variable
- **Evidence**: the source → sink → path fragments the detectors and filters produced
- **Pipeline Assessment**: `Suspicion Level (pipeline prior, not a verdict)` and `AI Verdict` (`_unclassified_` until the AI classifies, then the verdict plus a link to the verdict file, or the dismissal reason)
- **Fix Suggestion**: generic per-type remediation guidance

The `Suspicion Level` is an internal convergence prior (see CLAUDE.md, "Pipeline
Confidence Tiers"), never an AI conclusion — which is why the candidate file has
no `Status` line at all.

Filename format: `NNN_<filename>_<line>.md`, NNN being a zero-padded sequence number within the vulnerability type directory.

### Verdict Markdown (`findings/<vuln-type>/NNN_<file>_<line>_<verdict>.md`)

Written when the AI persists a finding (`secguard report --write`, or an A5
`--review` that changes the verdict), and re-derived by `--audit`:
- **Location** / **Evidence**: carried over from the candidate evidence when available, otherwise from the persisted finding
- **Code Context**: the source region around the finding, gutter-numbered with the reported line marked `>` — so the verdict can be judged without opening an editor
- **Classification**: `- **Status:** confirmed (severity: high, confidence: 90%)` — the AI verdict, with no pipeline prior mixed in
- **Summary** / **Reasoning** / **Exception Check** / **Fix Strategy**: the AI's structured justification and concrete fix (falling back to the generic **Fix Suggestion** when the AI supplied no fix)

Example Code Context block:

```
`/repo/src/tc01.c:15-31` — line 30 is the reported location.

  28 | int tc01_null_return(int id) {
  29 |     Node *node = get_node(id);
> 30 |     return node->value;
  31 | }
```

The window is ±15 lines by default. `--context-lines <n>` changes it globally
(`secguard report --context-lines 25 --audit ...`); `--context-lines 0` disables
source embedding entirely, for repositories whose source must not be copied into
report artifacts. The same setting drives the SARIF `region.snippet` /
`contextRegion.snippet` fields.

The verdict suffix is mandatory: `_confirmed` or `_suspected`. A file with no
suffix (or a `_dismissed` one) is stale and is removed by the next `--audit`.

### scan.log

Newline-delimited JSON (NDJSON) runtime log for the scan round. Each line is a structured JSON object emitted by the Go `slog` JSON handler, containing `time`, `level`, `msg`, and any structured key-value pairs. Example:

```json
{"time":"2026-08-11T14:30:22.123Z","level":"INFO","msg":"indexer starting","path":"/abs/path","files":42}
{"time":"2026-08-11T14:30:23.456Z","level":"WARN","msg":"memory_leak: CFG construction degenerate","function":"get_ptr"}
```

The file is created at scan start (truncated if it exists) and closed/flushed before the `latest` symlink is updated, so `scans/latest/scan.log` is always complete when `latest` is resolved. If the log file cannot be created or written, the scan continues with stderr-only logging and emits a warning.

## Database Location

The SQLite database (`sgre.db`) is stored at `.codeagent/secguard-clang/.sgre/sgre.db` (sibling of `scans/`). This directory is created automatically by the `secguard_scan` and `secguard_index` tools if it does not exist. The database contains:
- Program graph tables: `files`, `functions`, `call_graph_edges`, `data_flow_edges`, `global_vars`, `type_aliases`
- Security event tables: `security_events`, `function_summaries`
- Findings table: `findings` (written by `secguard_report` tool)

## Tool Integration

| Tool | DB Path | Output Dir |
|------|---------|------------|
| `secguard_scan` | `.codeagent/secguard-clang/.sgre/sgre.db` (auto-created) | `.codeagent/secguard-clang/scans/<scan-id>/` (auto-created) |
| `secguard_index` | `.codeagent/secguard-clang/.sgre/sgre.db` (auto-created) | N/A |
| `secguard_plan` | `.codeagent/secguard-clang/.sgre/sgre.db` | N/A |
| `secguard_status` | `.codeagent/secguard-clang/.sgre/sgre.db` | N/A |
| `secguard_report` | `.codeagent/secguard-clang/.sgre/sgre.db` (auto-created) | `findings/<vuln-type>/` inside the scan dir — pass `scan_id` **and** `output_dir` |
| `secguard_db` | `.codeagent/secguard-clang/.sgre/sgre.db` (read-only) | N/A |

## Agent Workflow

1. Call `secguard_scan` → returns `output_dir`, `candidates_sarif`, `sarif` (verdict stage, not yet written), `report_md`, `db_path`, `scan_id`
2. Read `report.md` for human-readable summary (or read `scans/latest/report.md` directly — the `latest` symlink always points to the most recent completed scan, so CI/CD pipelines can use a fixed path without parsing the scan_id)
3. Read candidate evidence in `candidates/<vuln-type>/` for candidates whose evidence is ambiguous
4. Load matching skills for classification guidance
5. Classify each candidate as confirmed/suspected/false-positive
6. Call `secguard_report` with the `findings` array **plus `scan_id` and `output_dir`** to persist the classification; each confirmed/suspected verdict materializes as `findings/<vuln-type>/NNN_..._<verdict>.md`, each dismissal is recorded without a file. A `per_finding_warning` in the response means the verdict never reached `findings/` — fix the call and write again.
7. Present summary table to user, referencing SARIF and Markdown output paths
