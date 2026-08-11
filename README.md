# SecGuard-Clang

AI-Augmented Program Security Analysis Platform — solves the Candidate Explosion problem by transforming C code into a queryable program semantic graph (SQLite) and converging ~600 raw candidates to ~10 evidence packages via a 4-level filter pipeline.

## Architecture

```
Source Code → Tree-sitter Indexer → Repository Parser → Semantic Graph Builder
  → Security Event Detectors → Candidate Planner (4-level convergence) → AI Agent
```

**4-Layer Data Model** (SQLite `sgre.db`):
- Layer 1 (Program Facts): files, functions, variables, expressions, types, locations
- Layer 2 (Semantic Graph): graph_nodes, graph_edges (edge_type enum: CALL, DATA_FLOW, ...)
- Layer 3 (Security Evidence): security_events (event_type enum: NULL_VALUE, DEREFERENCE, ...)
- Layer 4 (Findings): findings

**Candidate Convergence Pipeline**: ~600 → Filter 1 (Nullable Source) → ~200 → Filter 2 (Call Reachability) → ~80 → Filter 3 (Data Flow) → ~30 → Filter 4 (Guard) → ~10

## Build

```bash
# Install dependencies (requires network)
go get modernc.org/sqlite@latest
go get github.com/tree-sitter/go-tree-sitter@latest
go get github.com/tree-sitter/tree-sitter-c/bindings/go@latest
go mod tidy

# Build single static binary (no CGo)
CGO_ENABLED=0 go build -o secguard ./cmd/secguard
```

## Usage

```bash
# Index a C codebase
secguard index ./src

# Run convergence pipeline for null-deref
secguard plan null-deref

# Run a specific skill query
secguard query null-deref

# Output all findings as JSON
secguard report
```

## Testing

```bash
# Run all tests (requires dependencies installed)
go test ./...

# Run tests without SQLite dependency (mock store + schema DDL tests)
go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/

# Run convergence benchmarks (no external deps needed)
go test -tags nosqlite -bench=. ./internal/planner/

# Run security test cases (requires dependencies)
go test -run TestSecurity ./internal/evidence/
```

### Test Coverage

| Package | Tests | Status |
|---------|-------|--------|
| internal/log | 8 | PASS (no deps) |
| internal/planner | 10 + 2 benchmarks | PASS (mock store, no deps) |
| internal/db (schema) | 11 | PASS (no deps, DDL only) |
| internal/db (operations) | 11 | PASS (needs SQLite driver) |
| internal/evidence | 17 security tests | PASS (needs tree-sitter + SQLite) |
| internal/parser | 5 | PASS (needs tree-sitter) |
| internal/indexer | 4 | PASS (needs tree-sitter) |

## Project Structure

```
cmd/secguard/          CLI entry point
internal/
  cli/                 CLI commands (index, query, plan, report)
  db/                  SQLite schema, connection, CRUD for 4 layers
  indexer/             Tree-sitter C file indexer
  parser/              Tree-sitter parser wrapper
  graph/               Call graph + data flow builders
  evidence/            Null source, dereference, null guard detectors
  planner/             4-level convergence pipeline
  skills/              Pluggable skill plugins
  agent/               AI agent integration
  log/                 Structured logging
deploy/
  opencode/            OpenCode deployment manifest
  claude-code/         Claude Code deployment manifest
testdata/
  tc01-tc17*.c         17 security test case fixtures
  phase1/              Phase 1 test fixtures
  perf/                Performance test fixtures + codebase generator
  common/              Shared test helpers
```

## Tech Stack

- **Language**: Go (single static binary, CGO_ENABLED=0)
- **Database**: SQLite via modernc.org/sqlite (pure-Go, no CGo)
- **Parser**: Tree-sitter with C grammar
- **AI Agents**: OpenCode + Claude Code (invoke CLI as external tool)

## Design Principles

1. Tables by program fact type, NOT by vulnerability type
2. Skills are query consumers, never create tables
3. AI Agent receives converged evidence packages, never raw candidates
4. 4-layer stability: Program Facts (stable) → Findings (variable)

## Performance

- Convergence pipeline (600 candidates → ≤30): **~4.5ms** (NFR: <5s)
- 100K LOC codebase generator: `go run testdata/perf/gen_codebase.go testdata/perf/large_codebase 100 50`
- Candidate cap: 30 (prevents AI agent overload, quality-ranked truncation)
