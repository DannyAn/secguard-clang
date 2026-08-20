# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Go Module Location

The Go module lives in **`sgre/`** (module `github.com/DannyAn/secguard-clang`), not the repo root. The repo root holds the extension/deploy scaffolding and docs. **Run all `go` commands from `sgre/`.**

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
3. **`internal/evidence`** — 22 detectors (`null_source.go`, `dereference.go`, `buffer_overflow.go`, ...). Each detector implements the `Detector` interface and writes `security_events`. **Detectors self-register in `registry.go` via `init()`** — adding a detector means a new `RegisterDetector` line, nothing else.
4. **`internal/planner`** — the convergence pipeline. `Planner.Plan()` seeds candidates by event type, runs a per-vuln-type filter chain, dedups, and ranks — it returns **all** deduped candidates (no cap/truncation; the AI agent reviews every one in batches). Filters implement the `Filter` interface (`Apply(ctx, []Candidate) ([]Candidate, error)`).
5. **`internal/agent`** — formats converged evidence for the AI agent consumer.
6. **`internal/report`** — writes SARIF 2.1, a markdown summary, and per-finding markdown files.

**How a vulnerability type is wired end-to-end** (the piece that spans many files): an evidence detector emits a `security_events` row → a `VulnTypeSpec` registered in `internal/planner/registry.go` maps the type to its **CWE** (`VulnTypeSpec.CWE` — the single source of truth for the CWE↔vuln-type mapping; `report.VulnToCWE`, `db.SupportedFindingCWEs`, `planner.TypeForCWE`, and `secguard types` all derive from it, never hardcode a parallel map), seed event + filter chain → `getFilters()` in `planner.go` supplies the filters → a matching agent skill in `.claude/skills/<type>/SKILL.md` gives the AI agent classification rules. Adding a vuln type touches all four of these (and the CWE comes for free from the `VulnTypeSpec`).

**Graph-based convergence** (the `graph` layer is consumed, not just built): `internal/graph/control_flow.go` builds a statement-level CFG (`BuildStmtCFG`, with `Reaches`/`ReachesAvoiding`/`NodeAt`), and `internal/planner/null_flow.go` exposes a reusable *reaching-sources* dataflow engine (`flowAnalyzer.analyzeFlow`, `flowResult.reaching`/`reachingAtExit`) — a monotone set-of-source-IDs lattice with gen/kill/copy. This engine is the shared best practice that came out of the null-deref spike and is consumed by:

- **null-deref** — `NullableSourceFilter` (`filter_nullable_source.go`) seeds gen from `NULL_VALUE` events, kill from definite non-null reassignments (`v = &x` / `v = ""` / `v = arr`), copy from stored `DATA_FLOW` edges + AST assignments; it drops a dereference only when no null source can reach it. Falls back to the old line-order heuristic when the parser/file is unavailable (mock tests).
- **use-after-free** — `LifetimeFilter` (`filter_lifetime.go`) uses `BuildStmtCFG.Reaches(freeNode, useNode)` to drop only free→use pairs on mutually-exclusive branches, replacing the old coarse `graph.BuildCFG`/`CanReach`.

See `examples/nullflow-demo/` for a runnable null-deref sample. `memory-leak`/`resource-leak` still do path analysis in the detector (`memory_leak.go`'s `hasLeakingPath`, old `graph.BuildCFG`); migrating them to the new CFG needs ownership-transfer-aware analysis (return-to-caller / store-to-global), not plain reachability, so it is left as a follow-up.

### The 4-Layer Data Model (SQLite `sgre.db`)

- **Layer 1 — Program Facts** (most stable): `files`, `functions`, `variables`, `expressions`, `types`, `locations`
- **Layer 2 — Semantic Graph**: `graph_nodes`, `graph_edges` (`edge_type` enum: `CALL`, `DATA_FLOW`, `OWNERSHIP_TRANSFER`, `RELEASE`, `ALIAS`, `PARAM_BINDING`, `RETURN`)
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
secguard scan <path>     Full pipeline: index + plan all registered vuln types + report
secguard status          Index status (files, functions, staleness)
secguard query <skill>   Run a skill query
secguard plan <vuln>     Run convergence for one vulnerability type
secguard report          Output all findings as JSON
secguard types           List all vulnerability types + CWE (JSON)
secguard schema [table]  Show a table's schema (columns/types)
secguard db <sql>        Execute a SQL query, return JSON
```

`--db <path>` overrides the DB (default `./sgre.db`). All output is JSON on stdout (machine-consumed by the agent).

## Multi-Platform Agent Extension (`extension/`)

SecGuard targets three AI-agent platforms with a **shared-core + thin-wrapper** design:

- `extension/shared/` is the single source of truth: agent skills (`SKILL.md` files), `agent-body.md` (the security-auditor prompt), `command-instructions.md`.
- `extension/opencode/` and `extension/claude-code/` are thin platform wrappers using `{{include shared/...}}` directives, expanded at build time by `release/build-packages.sh`.
- `extension/deepseek-harness/` is a DSH agent preset (`preset.yml` + `agent.cordis.yml`, persona = `dsh-persona`), installed by `release/install-dsh.sh` into `~/.dsh/.agent-presets/secguard/`.
- The **installed copies** live at `.opencode/` and `.claude/` in the repo root. The `security-auditor` subagent (`.claude/agents/security-auditor.md`) is the consumer: it runs `secguard scan/plan`, loads per-type skills for classification, and persists findings.
- `.claude/settings.json` pre-approves `Bash(secguard *)` and emits a staleness hint on any `Edit|Write` (re-run `/secguard` after editing source).
- **Edit `extension/shared/`, never the installed copies** — the installed files are generated.

## Output Protocol

Scan output is written to `.codeagent/secguard-clang/scans/<scan-id>/` (`scan-id` = `YYYY-MM-DD_HHMMSS_<6-hex>`): `sarif.sarif` (SARIF 2.1), `report.md`, and per-finding `<vuln-type>/NNN_<file>_<line>.md`. The DB lives at `.codeagent/secguard-clang/.sgre/sgre.db`. See `docs/output-protocol.md` for the full contract.

## Test Fixtures

- `sgre/testdata/tc01-tc70*.c` — 74 security test fixtures (each targets a detector or edge case).
- `sgre/testdata/phase1`–`phase7` — staged fixtures for the pipeline phases.
- `sgre/testdata/perf/gen_codebase.go` — generates large synthetic codebases for perf testing: `go run testdata/perf/gen_codebase.go testdata/perf/large_codebase 100 50`.

## Supported Vulnerability Types (20)

Each is registered as a `VulnTypeSpec` in `internal/planner/registry.go` and has a
corresponding agent skill under `.claude/skills/`. The authoritative runtime list
is `secguard types` — do not hardcode this list in tooling (see the OpenCode tool
wrappers, which defer type validation to the binary). Each `VulnTypeSpec` carries
its `CWE` field; `planner.AllCWEs()` / `CWEForType()` / `TypeForCWE()` are the
only derived APIs — `db.SupportedFindingCWEs` is injected from `planner.AllCWEs()`
at CLI startup (`cli/root.go`), and the TS tool wrappers never hardcode CWE lists.

`null-deref`, `buffer-overflow`, `memory-leak`, `injection`, `resource-leak`,
`uninit`, `use-after-free`, `double-free`, `format-string`, `integer-overflow`,
`race-condition`, `hardcoded-secret`, `deadlock`, `crypto-misuse`,
`out-of-bounds`, `divide-by-zero`, `unchecked-return`, `path-traversal`,
`sizeof-misuse`, `signed-compare`.

`out-of-bounds` (CWE-125) shares the
`BUFFER_ACCESS` seed event with `buffer-overflow`: read-flavored categories
(`array_oob_read`, `heap_oob_read`) route to it, write-flavored categories
(`buffer_overflow`, `array_oob_write`, `heap_oob_write`, `format_overflow`)
route to `buffer-overflow`. The split lives in the `Categories` field of each
`VulnTypeSpec`.

## Review / Inspection Scope (READ THIS BEFORE EXPLORING)

**Do not inspect dot-prefixed directories unless there is a concrete reason.**

Directories like `.claude/`, `.opencode/`, `.codeagent/`, `.git/`, `.tools/`,
`.arts/`, `.remember/` are either generated, runtime, or tool-private.
Inspecting them during a code review:

1. **Wastes tokens** — `.git/` alone can be hundreds of MB of objects; `.claude/`
   and `.opencode/` are expanded copies of `extension/shared/` that duplicate
   content already reviewable at the source.
2. **Produces false findings** — a "drift" between `extension/shared/` and
   `.claude/` is not a release blocker; `.claude/` is regenerated on install.
   Reporting it as a BLOCKER misleads the user.
3. **Misses real issues** — token budget spent on generated copies is budget
   not spent on the actual source in `sgre/` and `extension/shared/`.

**The review surface for a release is:**

- `sgre/` — all Go source, tests, testdata
- `extension/shared/` — skills, agent-body.md, command-instructions.md (the
  single source of truth for agent behavior)
- `extension/opencode/`, `extension/claude-code/`, `extension/deepseek-harness/` — thin wrappers (only the
  wrapper-specific parts; the `{{include shared/...}}` directives are expanded
  at build time)
- `release/` — build/install scripts
- Root docs (`README.md`, `README-CN.md`, `QUICKSTART.md`, `CLAUDE.md`, `CHANGELOG.md`, `VERSION`)

If a finding is *only* reproducible in a dot-prefixed generated directory and
not in the source it was generated from, it is an **install-time issue**, not
a release blocker — note it and move on.

## Release Process

Releases are automated via GitHub Actions (`.github/workflows/release.yml`),
triggered by pushing a `v*` tag. The workflow builds 4 platform binaries
(linux-amd64 musl-static, windows-amd64, darwin-arm64, darwin-amd64),
assembles a single `dist/secguard-<version>.zip` + `SHA256SUMS`, and publishes
a GitHub Release with `CHANGELOG.md` as the body.

**Steps to release version `X.Y.Z`:**

1. **Update version files** (if not already):
   - `VERSION` → `X.Y.Z`
   - `sgre/internal/cli/root.go` `var Version` → `"X.Y.Z"` (fallback)
   - `sgre/internal/report/protocol.go` `var ToolVersion` → `"X.Y.Z"` (fallback)
   - `CHANGELOG.md` → add `## [X.Y.Z] - <date>` section

2. **Verify build & tests pass**:
   ```bash
   cd sgre
   go build -buildvcs=false ./...
   go test -buildvcs=false ./...
   go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/
   ```

3. **Commit & push to main**:
   ```bash
   git add -A
   git commit -m "chore(release): prepare vX.Y.Z"
   git push origin main
   ```

4. **Create & push the tag** (triggers the release workflow):
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

5. **Monitor the workflow**: the GitHub Actions run builds all platforms and
   auto-creates the Release. Check at
   `https://github.com/DannyAn/secguard-clang/actions`. If any platform build
   fails, fix and re-tag (`git tag -d vX.Y.Z && git tag vX.Y.Z && git push origin vX.Y.Z --force`).

**Note**: `release/build-packages.sh` builds locally (for testing); the CI
workflow is the canonical release path. Local builds use `build.sh` for
development. The `--assemble-only` flag in CI assembles the zip from
pre-built artifacts uploaded by the build matrix.
