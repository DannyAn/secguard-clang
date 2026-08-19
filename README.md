<div align="center">

> **English** · [中文版](README-CN.md)

# SecGuard-Clang

### AI-Augmented Security Analysis Platform for C

**Solves the "candidate explosion" problem with a 4-level convergence pipeline — shrinking ~600 raw candidates into ~10 high-quality evidence packages that an AI agent classifies.**

`v0.3.2` · `Go 1.25` · `Tree-sitter` · `SQLite` · `OpenCode / Claude Code / DeepSeek Harness`

</div>

---

## 🏆 Why is SecGuard world-class?

**In one sentence: SecGuard is the only C security analysis platform built natively for AI agents.** Traditional scanners (CodeQL / Infer / Coverity / Semgrep) are built for *humans reading reports* — they routinely emit thousands of raw alerts that drown an LLM. SecGuard compresses ~600 raw candidates into ~10 high-confidence evidence packages via 4-level convergence, so the AI only judges what is genuinely suspicious.

### Capabilities others lack (blue ocean)

1. **It even catches misuse of "safe" functions** — the industry almost universally treats `_s` functions (`memcpy_s` / `strcpy_s` / `scanf_s`) as unconditionally safe and skips them. SecGuard validates each size argument against the actual buffer contract: `char buf[10]; memcpy_s(buf, 100, src, 50)` — a "lying size" — is still flagged as an overflow.
2. **It uses the LLM as an analysis engine** — for the fuzzy boundaries static analysis cannot prove (does variable `n` actually blow up `malloc(n)`?), SecGuard recognizes them, packages the evidence, and hands them to the AI to reason about, instead of fabricating a possibly-wrong math domain.

### Benchmark against industry leaders (✅ strong · ⚠️ on par · ❌ weak)

| Capability | CodeQL | Infer | Coverity | Semgrep | **SecGuard** |
|---|---|---|---|---|---|
| Path-sensitive dataflow | ✅ | ✅ | ✅ | ❌ | ✅ |
| Cross-function analysis | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| Taint tracking | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| Alias analysis | ✅ | ✅ | ✅ | ❌ | ✅ |
| Numeric range analysis | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| FP suppression / baseline / CI gating | ✅ | ✅ | ✅ | ✅ | ✅ |
| SARIF code navigation | ✅ | ⚠️ | ✅ | ✅ | ✅ |
| Parallelism + timeout | ✅ | ✅ | ✅ | ✅ | ✅ |
| Incremental indexing | ✅ | ✅ | ✅ | ✅ | ✅ |
| Remediation advice | ⚠️ | ⚠️ | ✅ | ✅ | ✅ |
| **AI-agent native** | ❌ | ❌ | ❌ | ❌ | ✅ |

> See [docs/pk/competitive-analysis.md](docs/pk/competitive-analysis.md) for a capability-by-capability breakdown including SecGuard's implementation mechanism.

### Hard numbers (verifiable)

| Metric | Value |
|---|---|
| Vulnerability types / detectors | **20 / 22**, full CWE mapping |
| Convergence efficiency | ~600 raw alerts → **~10 evidence packages** (~4.5ms) |
| Benchmark regression gate | 77 cases, **100% precision / 100% recall** (TP=43 / FP=0 / TN=34 / FN=0) |
| Regression tests | 74 security fixtures · 244 test functions, `go test -race` with 0 data races |
| Delivery form | Static binaries for Linux / Windows / macOS + OpenCode / Claude Code / DeepSeek Harness |

### Plain-language conclusion

- **Stronger than Semgrep**: Semgrep only does textual pattern matching; SecGuard genuinely analyzes execution paths, dataflow, and cross-function propagation.
- **On par with Infer**: single-function precision analysis is at the same tier.
- **Approaching CodeQL / Coverity**: the only remaining gap is numeric range analysis, largely compensated by "AI-reasoning fallback" — see [docs/pk/competitive-analysis.md](docs/pk/competitive-analysis.md).

---

## What is SecGuard?

SecGuard is not a traditional static analysis tool. It is a **security-analysis extension for AI agents** — deployed into OpenCode, Claude Code, or DeepSeek Harness so an AI agent gains deep C code-auditing capability.

The core idea: traditional static analyzers produce a flood of raw candidates (high false-positive rate); handing them to an AI causes **context explosion**. SecGuard performs 4-level convergence on a semantic graph + dataflow foundation, and hands only high-quality evidence packages to the AI agent for classification.

```
                    ┌──────────────────────────────────────────────────┐
                    │          AI Agent (OpenCode / Claude Code / DSH)    │
                    │                                                      │
                    │  secguard scan ──→ converged evidence ──→ classify   │
                    │  secguard plan  ──→ per-type evidence ──→ classify   │
                    │  secguard report ──→ write findings                  │
                    └────────────────────────┬─────────────────────────┘
                                             │ shell call
                    ┌────────────────────────▼─────────────────────────┐
                    │           secguard binary (sgre engine)             │
                    │                                                      │
                    │  index → graph → detect → plan(converge) → report    │
                    └────────────────────────┬─────────────────────────┘
                                             │
                    ┌────────────────────────▼─────────────────────────┐
                    │              SQLite semantic graph (sgre.db)        │
                    │                                                      │
                    │  Layer 1: program facts  (files, functions, vars)    │
                    │  Layer 2: semantic graph (call graph, dataflow, CFG) │
                    │  Layer 3: security evidence (security_events)        │
                    │  Layer 4: findings     (written by the AI)           │
                    └──────────────────────────────────────────────────┘
```

## Architecture

### Pipeline

```
 C source code
    │
    ▼
┌───────────────┐
│  Tree-sitter   │  incremental indexing (skips unchanged files by checksum)
│  Indexer       │  → Layer 1: program facts
└───────┬───────┘
        ▼
┌───────────────┐
│  Semantic      │  call graph + dataflow + reachability + statement-level CFG
│  Graph Builder │  → Layer 2: semantic graph
└───────┬───────┘
        ▼
┌───────────────┐
│  22 Detectors  │  null-deref, buffer-overflow, injection, ...
│  (self-register)│  → Layer 3: security evidence (security_events)
└───────┬───────┘
        ▼
┌───────────────┐
│  Planner       │  4-level convergence pipeline
│  (convergence) │
└───────┬───────┘
        │
        │  ~600 raw candidates
        │     │
        │     ▼  Filter 1: nullable-source analysis (reaching-sources dataflow)
        │   ~200
        │     │
        │     ▼  Filter 2: call reachability (call graph)
        │    ~80
        │     │
        │     ▼  Filter 3: dataflow validation (CFG + guard)
        │    ~30
        │     │
        │     ▼  Filter 4: dedup + risk ranking
        │    ~10  high-quality evidence packages
        │
        ▼
┌───────────────┐
│  AI Agent      │  per-type batch classification: confirmed / suspected / false-positive
│  (classifier)  │  → Layer 4: findings
└───────┬───────┘
        ▼
┌───────────────┐
│  Report        │  SARIF 2.1 + Markdown + per-finding Markdown
└───────────────┘
```

### 4-layer data model

| Layer | Content | Stability | Tables |
|----|------|--------|-----|
| **Layer 1** | program facts | most stable | `files`, `functions`, `variables`, `expressions`, `types`, `locations` |
| **Layer 2** | semantic graph | stable | `graph_nodes`, `graph_edges` (CALL, DATA_FLOW, OWNERSHIP_TRANSFER, RELEASE, ALIAS, PARAM_BINDING, RETURN) |
| **Layer 3** | security evidence | medium | `security_events` (NULL_VALUE, DEREFERENCE, BUFFER_ACCESS, ...) |
| **Layer 4** | findings | most volatile | `findings` (written by the AI agent) |

### Multi-platform extension architecture

```
extension/
├── shared/                    ← single source of truth (edit here)
│   ├── agent-body.md          ← AI agent prompt (workflow + classification rules)
│   ├── command-instructions.md ← /secguard command instructions
│   └── skills/                ← 20 vulnerability-type skills
│       ├── null-deref/SKILL.md
│       ├── buffer-overflow/SKILL.md
│       └── ...
├── opencode/                  ← OpenCode thin wrapper
│   ├── tools/*.ts             ← 7 TypeScript tools
│   └── extension.json
├── claude-code/               ← Claude Code thin wrapper
│   └── ...
└── deepseek-harness/          ← DeepSeek Harness thin wrapper (agent preset)
    ├── preset.yml             ← preset metadata
    └── agent.cordis.yml       ← Cordis composition (persona + tools + skill roots)
```

For OpenCode / Claude Code, `release/build-packages.sh` expands `shared/` and installs into `.opencode/` and `.claude/`.
For DeepSeek Harness, `release/install-dsh.sh` installs the preset into `~/.dsh/.agent-presets/secguard/` (skills copied from `shared/`).

## Quick start

### Option 1: install from a release package (recommended)

```bash
# download the release package
curl -L https://github.com/DannyAn/secguard-clang/releases/latest/download/secguard-0.3.2.zip -o secguard.zip
unzip secguard.zip

# install (auto-detects OS × arch; installs into OpenCode + Claude Code)
./install.sh

# verify
secguard --version
```

The install script supports:

```bash
./install.sh --target opencode       # OpenCode extension only
./install.sh --target claude-code    # Claude Code extension only
./install.sh --no-binary             # extension only, skip the binary
./install.sh --verify                # post-install self-check
./install.sh --uninstall --yes       # uninstall
```

### Option 2: build from source

```bash
git clone https://github.com/DannyAn/secguard-clang.git
cd secguard-clang

# build the binary + install the extension
./build.sh --install

# or build the binary only
./build.sh              # → bin/secguard

# build a release package
./build.sh --package
```

For a quick dev-mode deploy (build + install the extension into user-level config dirs), use `./deploy.sh [opencode|claude-code|all] [--no-binary]`.

### Option 3: DeepSeek Harness (DSH)

SecGuard ships a DSH agent preset (a Cordis composition). After installing, select the
"SecGuard Security Audit" preset in DSH to give an agent C security-auditing capability:

```bash
# 1) ensure the secguard binary is on PATH (see option 1/2)
# 2) install the DSH preset (composition + 20 skills → ~/.dsh/.agent-presets/secguard/)
./release/install-dsh.sh

# 3) select the "SecGuard Security Audit" preset in DSH, then chat:
#    > Scan the src/ directory for security vulnerabilities
#    > Look for buffer-overflow and null-deref issues
```

The DSH "role" is the persona (`dsh-persona` inside `agent.cordis.yml`); external users
select the preset to get an agent focused on C security auditing, without touching
OpenCode or Claude Code.

### Using it inside an AI agent

After installation, chat directly in OpenCode, Claude Code, or DeepSeek Harness:

```
> Scan the src/ directory for security vulnerabilities
> Look for null-deref, buffer-overflow issues
> Audit ./src for security
```

The AI agent automatically runs `secguard scan`, loads the matching skill, classifies, and emits a report.

### Using the CLI directly

```bash
# full scan (index + detect + converge + report)
secguard scan ./src

# list supported vulnerability types
secguard types

# show index status
secguard status

# run convergence for a single vulnerability type
secguard plan null-deref

# query findings
secguard report

# execute a SQL query
secguard db "SELECT * FROM findings WHERE status='confirmed'"
```

## Supported vulnerability types (20)

| Type | CWE | Type | CWE |
|---------|-----|---------|-----|
| `null-deref` | CWE-476 | `hardcoded-secret` | CWE-798 |
| `buffer-overflow` | CWE-787 | `deadlock` | CWE-667 |
| `memory-leak` | CWE-401 | `crypto-misuse` | CWE-327 |
| `injection` | CWE-78 | `out-of-bounds` | CWE-125 |
| `resource-leak` | CWE-404 | `divide-by-zero` | CWE-369 |
| `uninit` | CWE-457 | `unchecked-return` | CWE-252 |
| `use-after-free` | CWE-416 | `path-traversal` | CWE-22 |
| `double-free` | CWE-415 | `sizeof-misuse` | CWE-467 |
| `format-string` | CWE-134 | `signed-compare` | CWE-681 |
| `integer-overflow` | CWE-190 | `race-condition` | CWE-362 |

Each type has a corresponding AI agent skill (`extension/shared/skills/<type>/SKILL.md`) with classification rules and false-positive recognition guidance.

## CLI commands

| Command | Description |
|------|------|
| `secguard scan <path>` | full pipeline: index + all detectors + convergence + report |
| `secguard plan <vuln>` | run the convergence pipeline for one vulnerability type |
| `secguard index <path>` | index only (skip detectors and convergence) |
| `secguard status` | index status (file count, function count, staleness) |
| `secguard types` | list all vulnerability types + CWE (JSON) |
| `secguard schema [table]` | show a table's schema (columns/types; use before writing SQL) |
| `secguard report` | output all findings (JSON) |
| `secguard db <sql>` | run a SQL query against sgre.db (read-only) |

Global options: `--db <path>` (override DB path), `--exclude <dirs>` (exclude directories), `--version`, `--help`

## Output

Scan results are written to `.codeagent/zhuque-secguard/scans/<scan-id>/`:

```
scans/2026-08-17_062452_e32eb1/
├── sarif.sarif                    ← SARIF 2.1 (IDE/CI integration)
├── report.md                      ← Markdown summary (candidate list)
├── audit-report.md                ← AI audit report (classification stats)
├── buffer-overflow/
│   ├── 001_allocator_99.md       ← per-finding evidence
│   └── 002_parser_20.md
├── null-deref/
│   └── 001_network_45.md
└── ...
```

## Tech stack

| Component | Technology | Notes |
|------|------|------|
| **Core engine** | Go 1.25 | single static binary, cross-platform |
| **Database** | SQLite (modernc.org/sqlite) | pure Go, no CGo dependency |
| **Parser** | Tree-sitter + tree-sitter-c | incremental C parsing |
| **Cross-compilation** | zig (musl/mingw) | static Linux/Windows binaries |
| **AI extension** | TypeScript/Bun | 7 OpenCode tools |
| **AI platforms** | OpenCode + Claude Code + DSH | shared core + thin wrappers |

## Project structure

```
secguard-clang/
├── sgre/                          # Go module (core engine)
│   ├── cmd/secguard/              # CLI entrypoint
│   └── internal/
│       ├── cli/                   # CLI command implementations
│       ├── db/                    # SQLite schema + CRUD
│       ├── indexer/               # Tree-sitter indexer
│       ├── parser/                # parser wrapper
│       ├── graph/                 # semantic graph builder (call graph/dataflow/CFG)
│       ├── evidence/              # 22 security detectors
│       ├── planner/               # 4-level convergence pipeline + filters
│       ├── agent/                 # AI agent integration
│       ├── report/                # SARIF + Markdown reporting
│       └── log/                   # structured logging
├── extension/                     # multi-platform AI agent extension
│   ├── shared/                    # shared core (skills + agent prompt)
│   ├── opencode/                  # OpenCode wrapper
│   ├── claude-code/               # Claude Code wrapper
│   └── deepseek-harness/          # DeepSeek Harness wrapper (agent preset)
├── release/                       # build/install tooling
├── examples/                      # samples and benchmarks
│   └── c-vuln-benchmark/          # 23 files / 77 test cases / 20 types
├── docs/                          # design docs
├── build.sh                       # build entrypoint
└── .github/workflows/             # CI release workflow
```

## Testing

```bash
cd sgre

# full suite (needs SQLite + tree-sitter)
go test ./...

# no-SQLite subset (mock store)
go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/

# convergence benchmark
go test -tags nosqlite -bench=. ./internal/planner/

# security test fixtures
go test -run TestSecurity ./internal/evidence/
```

## Design principles

1. **Tables are organized by program-fact type**, not by vulnerability type — avoiding schema explosion.
2. **Skills are query consumers** and never create tables — keeping concerns separated.
3. **The AI agent receives converged evidence packages only** and never raw candidates — this is the pipeline's core value.
4. **Single source of truth for CWE mapping** — `VulnTypeSpec.CWE` is the only truth; all consumers derive from it.
5. **Batch per vulnerability type** — avoiding AI agent context explosion.

## Performance

- Convergence pipeline (600 candidates → ≤30): **~4.5ms**
- Incremental indexing: skips unchanged files by checksum
- Large-codebase generator: `go run testdata/perf/gen_codebase.go testdata/perf/large_codebase 100 50`

## Related docs

- [CLAUDE.md](CLAUDE.md) — authoritative architecture (working guide for Claude Code)
- [CHANGELOG.md](CHANGELOG.md) — change log
- [docs/pk/competitive-analysis.md](docs/pk/competitive-analysis.md) — competitive analysis (vs CodeQL / Infer / Coverity / Semgrep)
- [docs/output-protocol.md](docs/output-protocol.md) — output contract
- [docs/parallelization-design.md](docs/parallelization-design.md) — parallelization design
- [examples/c-vuln-benchmark/](examples/c-vuln-benchmark/) — vulnerability benchmark suite
- [README-CN.md](README-CN.md) — 中文版

## License

Proprietary © Zhuque Security
