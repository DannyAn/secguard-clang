<div align="center">

> **English** · [中文版](README-CN.md)

# SecGuard-Clang

### Security analysis for C, built natively for AI agents

**A semantic-graph security engine that turns thousands of raw detector events into a small set of high-signal evidence packages an AI agent can actually reason over.**

`v0.8.0` · `Go 1.25` · `Tree-sitter` · `SQLite` · `OpenCode / OpenCode-NGA / Claude Code / Claude CAC / DeepSeek Harness`

</div>

---

## What is SecGuard?

SecGuard-Clang is a C security analysis platform split across two layers that each do what they are good at:

- **A deterministic engine** (`sgre`) indexes the codebase, builds a semantic graph (call graph, dataflow, control flow, alias and taint edges), runs self-registering detectors, and converges raw evidence into candidate leads. Where the graph can *prove* a defect, it auto-confirms it without AI involvement.
- **An AI agent layer** reviews only the remaining leads — packaged with the exact source statement, the pipeline's precomputed hint, and a small code-context window — and returns a single binary verdict per candidate: `confirmed` (persisted with reasoning and a fix) or `dismissed` (excluded, never persisted).

The value is the boundary between the two layers. Traditional scanners emit every raw alert, which drowns an LLM in false positives and wastes its context window. SecGuard instead hands the model compact, converged evidence and lets the model spend its reasoning budget on the cases the deterministic pipeline could not settle.

## Why it is different

- **Evidence packaging, not alert dumping.** The scan stage writes per-type candidate indexes (`Source` + `Hint` + `Evidence`) and per-candidate code context, so the agent classifies from structured evidence rather than re-reading the repository.
- **Contracts, not blanket "safe" exclusions.** A `_s` function is not assumed safe. `char buf[10]; memcpy_s(buf, 100, src, 50)` is a lying size and is reported as an overflow; a correct `memcpy_s(dst, sizeof(dst), src, 8)` is not.
- **Binary verdicts.** Every candidate ends as `confirmed` or `dismissed`. There is no lingering `suspected` pile for a developer to triage later; `findings/` and `result.sarif` contain only actionable results.
- **Reproducible artifacts.** One scan produces `report.md`, `audit-report.md`, `result.sarif`, `result.xlsx`, and a `findings/` tree, all re-derived from the same SQLite database.
- **Works where the engineer already works.** The same core ships as a thin extension for OpenCode, OpenCode-NGA, Claude Code, Claude CAC, and DeepSeek Harness, plus a standalone CLI for CI.

## The pipeline

```
 C source code
    │
    ▼
┌────────────────┐   tree-sitter incremental indexing
│  Indexer        │   (unchanged files skipped by checksum)
└───────┬────────┘
        ▼
┌────────────────┐   call graph + dataflow + CFG + alias/ownership edges
│  Semantic graph │
└───────┬────────┘
        ▼
┌────────────────┐   32 self-registering detectors
│  Detectors      │   (null-deref, buffer-overflow, injection, ...)
└───────┬────────┘
        ▼
┌────────────────┐   convergence filters: nullable-source, call-reach,
│  Planner        │   dataflow, dedup + risk ranking
└───────┬────────┘
        │
        ├── provable defects ──────────────► auto-confirmed (no AI review)
        │
        └── remaining leads ──► evidence packages ──► AI agent
                                  │
                                  │  single-pass binary verdict
                                  ▼
                            confirmed → persisted + fix strategy
                            dismissed → excluded, not persisted
                                  │
                                  ▼
┌────────────────┐   report.md · audit-report.md · result.sarif ·
│  Report / audit │   result.xlsx · findings/
└────────────────┘
```

The deterministic stages settle what they can prove or refute. The AI stage only classifies the residue and, for every confirmed finding, adds the `summary`, `reasoning`, `exception_check`, and `fix_strategy` a deterministic engine cannot synthesize.

## Supported vulnerability types

SecGuard ships 24 vulnerability types with a single source of truth for CWE mapping:

| Type | CWE | Type | CWE |
|---|---|---|---|
| `null-deref` | CWE-476 | `use-after-free` | CWE-416 |
| `buffer-overflow` | CWE-787 | `double-free` | CWE-415 |
| `out-of-bounds` | CWE-125 | `uninit` | CWE-457 |
| `memory-leak` | CWE-401 | `unchecked-return` | CWE-252 |
| `resource-leak` | CWE-404 | `format-string` | CWE-134 |
| `injection` | CWE-78 | `integer-overflow` | CWE-190 |
| `path-traversal` | CWE-22 | `divide-by-zero` | CWE-369 |
| `crypto-misuse` | CWE-327 | `hardcoded-secret` | CWE-798 |
| `deadlock` | CWE-667 | `race-condition` | CWE-362 |
| `dangerous-function` | CWE-676 | `signed-compare` | CWE-681 |
| `sizeof-misuse` | CWE-467 | `signal-handler` | CWE-479 |
| `argument-type` | CWE-686 | `data-representation` | CWE-843 |

Each type has a matching agent skill under `extension/shared/skills/<type>/SKILL.md` with classification rules and false-positive guidance.

## Quick start

### Install from a release package

```bash
curl -L https://github.com/DannyAn/secguard-clang/releases/latest/download/secguard-0.8.0.zip -o secguard.zip
unzip secguard.zip

# install into every supported agent surface + the CLI binary
./install.sh

# or target one surface
./install.sh --target opencode       # OpenCode
./install.sh --target opencode-nga   # OpenCode-NGA
./install.sh --target claude-code    # Claude Code
./install.sh --target claude-cac     # Claude CAC
./install.sh --no-binary             # extension only
./install.sh --verify                # post-install self-check
```

### Install a platform plugin from an AI Agent Market

Each release also ships `secguard-clang-plugins-<version>.zip`, which contains one self-contained plugin per platform (`secguard-clang-opencode`, `secguard-clang-opencode-nga`, `secguard-clang-claude-code`, `secguard-clang-claude-cac`). Upload the matching plugin to your market's extension entry, then install it in the agent TUI. The command namespace is `secguard-clang` on every platform. See `release/plugins-README.md` for the full matrix.

### Build from source

```bash
git clone https://github.com/DannyAn/secguard-clang.git
cd secguard-clang
./build.sh                 # binary → bin/secguard
./build.sh --install       # binary → ~/.local/bin
./build.sh --package       # release package
./deploy.sh all            # build + install the agent extensions
```

`./deploy.sh` targets `opencode`, `opencode-nga`, `claude-code`, `claude-cac`, `dsh`, or `all`, and accepts `--no-binary` to skip the binary build.

### DeepSeek Harness

```bash
./release/install-dsh.sh
```

Then select the **SecGuard Security Audit** preset in DeepSeek Harness.

## Usage

Inside an agent, just ask in natural language:

```
> Scan the src/ directory for security vulnerabilities
> Look for null-deref and buffer-overflow issues
```

Or drive the CLI directly:

```bash
secguard scan ./src        # index + graph + detect + converge + auto-confirm + candidates
secguard types             # authoritative vulnerability types + CWE
secguard status            # index status
secguard plan null-deref   # convergence for one type
secguard report            # read persisted findings
secguard metrics           # scan performance and convergence metrics
secguard schema findings   # table schema before raw SQL
secguard db "SELECT ..."   # read-only SQL against sgre.db
```

## Output

Scan results are written under `.codeagent/secguard-clang/scans/<scan-id>/`:

```
scans/<scan-id>/
├── candidates.sarif              # candidate stage (unclassified leads, level "note")
├── result.sarif                  # verdict stage (confirmed only)
├── report.md                     # verdict-stage report
├── audit-report.md               # per-type pipeline + AI classification statistics
├── result.xlsx                   # actionable findings export
├── candidates/<type>/            # pipeline evidence, grouped by vulnerability type
│   └── 001_allocator_99.md       # lead with embedded code context
└── findings/<type>/              # human review surface — confirmed verdicts only
    └── 001_allocator_99_confirmed.md
```

`findings/` and `result.sarif` contain only confirmed results. A dismissed candidate gets no finding file and is not persisted; the classification trail keeps the reason for auditability. Point CI at `result.sarif`: it cannot contain an unclassified lead.

Each verdict file is self-contained — location, evidence chain, the surrounding source with the reported line marked, the AI reasoning and exception check, and a paste-ready fix. Use `--context-lines <n>` to tune the embedded source window, or `0` to omit it.

## Architecture

### 4-layer data model

| Layer | Content | Stability | Tables |
|---|---|---|---|
| **1. Program facts** | files, functions, variables, expressions, types, locations | most stable | `files`, `functions`, `variables`, `expressions`, `types`, `locations` |
| **2. Semantic graph** | call/dataflow/control-flow/alias/ownership edges | stable | `graph_nodes`, `graph_edges` |
| **3. Security evidence** | detector events before convergence | medium | `security_events` |
| **4. Findings** | AI-confirmed and auto-confirmed verdicts | most volatile | `findings` |

### Multi-platform extension

```
extension/
├── shared/                      # single source of truth
│   ├── agent-body.md            # subagent role + classification contract
│   ├── command-instructions.md  # /secguard workflow
│   └── skills/                  # 24 vulnerability-type skills
├── opencode/                    # OpenCode wrapper + 9 MCP tools
├── opencode-nga/                # OpenCode-NGA wrapper (shares the same tools)
├── claude-code/                 # Claude Code wrapper
├── claude-cac/                  # Claude CAC wrapper
└── deepseek-harness/            # DeepSeek Harness agent preset
```

`shared/` is authoritative. `release/build-packages.sh` expands it into each platform package, and `release/check-extension-consistency.py` keeps tool registration, agent permissions, and the turn budget aligned across platforms.

## Tech stack

| Component | Technology | Notes |
|---|---|---|
| Core engine | Go 1.25 | single static binary, cross-platform |
| Database | SQLite (`modernc.org/sqlite`) | pure Go, no CGo dependency |
| Parser | Tree-sitter + tree-sitter-c | incremental C parsing |
| Cross-compilation | zig (musl/mingw) | static Linux/Windows binaries |
| AI extension | TypeScript/Bun | 9 OpenCode MCP tools |
| Agent surfaces | OpenCode, OpenCode-NGA, Claude Code, Claude CAC, DeepSeek Harness | shared core + thin wrappers |

## Project structure

```
secguard-clang/
├── sgre/                          # Go module (core engine)
│   ├── cmd/secguard/              # CLI entrypoint
│   └── internal/
│       ├── cli/                   # command implementations
│       ├── db/                    # SQLite schema + CRUD
│       ├── indexer/               # tree-sitter indexer
│       ├── parser/                # parser wrapper
│       ├── graph/                 # semantic graph builder
│       ├── evidence/              # self-registering detectors
│       ├── planner/               # convergence pipeline + filters
│       ├── report/                # SARIF / Markdown / XLSX reporting
│       └── log/                   # structured logging
├── extension/                     # multi-platform AI agent extension
├── release/                       # build/install tooling
├── examples/c-vuln-benchmark/     # C vulnerability benchmark
├── docs/                          # design docs
├── build.sh                       # build entrypoint
└── .github/workflows/             # CI release workflow
```

## Testing

```bash
cd sgre
go test ./...                        # full suite (SQLite + tree-sitter)
go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/   # no-SQLite subset
```

The `examples/c-vuln-benchmark` suite is a self-contained C regression fixture used as a CI gate for detector and planner changes.

## Design principles

1. **Program facts, not per-vulnerability tables.** Tables are organized by fact type, avoiding schema explosion as detector coverage grows.
2. **Skills are query consumers.** A skill classifies evidence and never creates schema.
3. **The AI sees converged evidence only.** Raw candidates stay out of the agent context.
4. **One source of truth for CWE.** `planner.VulnTypeSpec.CWE` is canonical; consumers derive from it.
5. **Dismissed is not persisted.** The review surface stays clean, and the final counts come from the audit summary, not from file listings.

## Related docs

- [CLAUDE.md](CLAUDE.md) — architecture and working guide
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [docs/output-protocol.md](docs/output-protocol.md) — output contract
- [docs/parallelization-design.md](docs/parallelization-design.md) — parallel dispatch design
- [examples/c-vuln-benchmark/](examples/c-vuln-benchmark/) — vulnerability benchmark suite
- [README-CN.md](README-CN.md) — 中文版

## License

Licensed under the [Apache License 2.0](LICENSE). © An Gang
