# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Go Module Location

The Go module lives in **`sgre/`** (module `github.com/DannyAn/secguard-clang`), not the repo root. The repo root holds the extension/deploy scaffolding and docs. **Run all `go` commands from `sgre/`.** The repo root is not a git repository.

## Build & Test

```bash
cd sgre

# Build
go build ./...                                   # compile everything
CGO_ENABLED=0 go build -o ../bin/secguard ./cmd/secguard   # single static binary

# Test
go test ./...                                    # full suite (needs SQLite + tree-sitter deps)
go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/   # no-SQLite subset
go test -tags nosqlite -bench=. ./internal/planner/                          # convergence benchmarks
go test -run TestSecurity ./internal/evidence/   # security test fixtures (needs deps)
```

- The `nosqlite` build tag (set in `internal/db/sqlite_driver.go`) swaps in a mock store so `log`, `planner`, and `db` schema tests run without the SQLite driver.
- `./build.sh` (repo root) builds to `bin/secguard` with flags `--test` and `--install`; it sets `CGO_ENABLED=1`, `GOFLAGS=-mod=mod`, and uses a private `GOCACHE`/`TMPDIR` under `sgre/`.

## What This Is

SecGuard-Clang is an AI-augmented C security analyzer. It transforms a C codebase into a queryable semantic graph in SQLite, emits raw security "candidates" from detectors, then runs a **convergence pipeline** to shrink ~600 raw candidates to ~10 high-quality evidence packages that an AI agent classifies. The whole point is solving the *candidate explosion* problem — the AI agent must only ever see converged evidence, never raw candidates.

```
Source Code → Tree-sitter Indexer → Semantic Graph Builder → Security Event Detectors
  → Candidate Planner (4-level convergence) → AI Agent
```

## Architecture (read in this order)

The pipeline is a chain of packages, each writing to the next layer of the DB:

1. **`internal/indexer`** — walks `*.c` files, parses with tree-sitter, and writes Layer-1 facts. Incremental: files unchanged by checksum are skipped.
2. **`internal/graph`** — builds the semantic graph (call graph, data flow, reachability, CFG) on top of the indexed facts.
3. **`internal/evidence`** — 17 detectors (`null_source.go`, `dereference.go`, `buffer_overflow.go`, ...). Each detector implements the `Detector` interface and writes `security_events`. **Detectors self-register in `registry.go` via `init()`** — adding a detector means a new `RegisterDetector` line, nothing else.
4. **`internal/planner`** — the convergence pipeline. `Planner.Plan()` seeds candidates by event type, runs a per-vuln-type filter chain, dedups, ranks, and caps at `MaxCandidates` (30). Filters implement the `Filter` interface (`Apply(ctx, []Candidate) ([]Candidate, error)`).
5. **`internal/agent`** — formats converged evidence for the AI agent consumer.
6. **`internal/report`** — writes SARIF 2.1, a markdown summary, and per-finding markdown files.

**How a vulnerability type is wired end-to-end** (the piece that spans many files): an evidence detector emits a `security_events` row → a `VulnTypeSpec` registered in `internal/planner/registry.go` maps the type to its seed event + filter chain → `getFilters()` in `planner.go` supplies the filters → a matching agent skill in `.claude/skills/<type>/SKILL.md` gives the AI agent classification rules. Adding a vuln type touches all four of these.

### The 4-Layer Data Model (SQLite `sgre.db`)

- **Layer 1 — Program Facts** (most stable): `files`, `functions`, `variables`, `expressions`, `types`, `locations`
- **Layer 2 — Semantic Graph**: `graph_nodes`, `graph_edges` (`edge_type` enum: `CALL`, `DATA_FLOW`, `OWNERSHIP_TRANSFER`, `RELEASE`, `BRANCH`, `ALIAS`)
- **Layer 3 — Security Evidence**: `security_events` (`event_type` enum: `NULL_VALUE`, `DEREFERENCE`, `NULL_GUARD`, `BUFFER_ACCESS`, ...)
- **Layer 4 — Findings** (most variable): `findings` (written by the AI agent)
- Support tables: `scan_stats` (pipeline metrics per scan/vuln type), `function_summary` (return-nullability input for the agent)

Schema is in `internal/db/schema.go` (`SchemaDDL`). CRUD is split per entity in `internal/db/crud_*.go` behind a `db.Store` interface (`store.go`), with a real SQLite impl (`store_impl.go`) and a mock (`testhelpers.go`).

### Design invariants (do not break)

- Tables are organized by **program fact type**, not by vulnerability type.
- Skills are **query consumers only** — they never create tables.
- The AI agent (via `security-auditor`) receives **converged evidence packages only**. It must not query `security_events` to recover filtered-out raw candidates — that defeats the pipeline. (Enforced by the agent prompt in `extension/shared/agent-body.md`.)
- Layer stability: Program Facts are stable; Findings vary per scan.

## CLI

`cmd/secguard/main.go` → `internal/cli/root.go` dispatches:

```
secguard index <path>    Index a C codebase
secguard scan <path>     Full pipeline: index + plan all 14 vuln types + report
secguard status          Index status (files, functions, staleness)
secguard query <skill>   Run a skill query
secguard plan <vuln>     Run convergence for one vulnerability type
secguard report          Output all findings as JSON
secguard db <sql>        Execute a SQL query, return JSON
```

`--db <path>` overrides the DB (default `./sgre.db`). All output is JSON on stdout (machine-consumed by the agent).

## Multi-Platform Agent Extension (`extension/`)

SecGuard targets two AI-agent platforms with a **shared-core + thin-wrapper** design:

- `extension/shared/` is the single source of truth: agent skills (`SKILL.md` files), `agent-body.md` (the security-auditor prompt), `command-instructions.md`.
- `extension/opencode/` and `extension/claude-code/` are thin platform wrappers using `{{include shared/...}}` directives, expanded at install time by `extension/install.sh`.
- The **installed copies** live at `.opencode/` and `.claude/` in the repo root. The `security-auditor` subagent (`.claude/agents/security-auditor.md`) is the consumer: it runs `secguard scan/plan`, loads per-type skills for classification, and persists findings.
- `.claude/settings.json` pre-approves `Bash(secguard *)` and emits a staleness hint on any `Edit|Write` (re-run `/secguard` after editing source).
- **Edit `extension/shared/`, never the installed copies** — the installed files are generated.

## Output Protocol

Scan output is written to `.codeagent/zhuque-secguard/scans/<scan-id>/` (`scan-id` = `YYYY-MM-DD_HHMMSS_<4-hex>`): `sarif.sarif` (SARIF 2.1), `report.md`, and per-finding `<vuln-type>/NNN_<file>_<line>.md`. The DB lives at `.codeagent/zhuque-secguard/.sgre/sgre.db`. See `docs/output-protocol.md` for the full contract.

## Test Fixtures

- `sgre/testdata/tc01-tc17*.c` — 17 security test fixtures (each targets a detector).
- `sgre/testdata/phase1`–`phase7` — staged fixtures for the pipeline phases.
- `sgre/testdata/perf/gen_codebase.go` — generates large synthetic codebases for perf testing: `go run testdata/perf/gen_codebase.go testdata/perf/large_codebase 100 50`.

## Supported Vulnerability Types (14)

`null-deref`, `buffer-overflow`, `memory-leak`, `injection`, `resource-leak`, `uninit`, `use-after-free`, `double-free`, `format-string`, `integer-overflow`, `race-condition`, `hardcoded-secret`, `deadlock`, `crypto-misuse` — each registered as a `VulnTypeSpec` in `internal/planner/registry.go`, each with a corresponding agent skill under `.claude/skills/`.
