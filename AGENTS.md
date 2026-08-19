# AGENTS.md

This file gives AI coding agents (Codex, Cursor, etc.) the project-specific
guidance they need. It is the cross-tool equivalent of `CLAUDE.md`; the two
are kept in sync. **Read `CLAUDE.md` for the full architecture** — this file
captures the conventions that prevent wasted effort and token burn.

## What This Is

SecGuard-Clang is an AI-augmented C security analyzer. The Go module lives in
**`sgre/`** (module `github.com/DannyAn/secguard-clang`), not the repo root.
The repo root holds extension scaffolding, release tooling, and docs.

## Build & Test

All `go` commands run from `sgre/`:

```bash
cd sgre
go build ./...
go test ./...                                              # full suite (needs SQLite + tree-sitter)
go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/   # no-SQLite subset
```

If `go build` fails with `error obtaining VCS status`, add `-buildvcs=false`.
If the default `GOCACHE` is not writable, set `GOCACHE=$PWD/.tmpcache
TMPDIR=$PWD/.tmpcache`.

## Source vs. Generated — Edit the Source, Never the Copy

| Layer | Path | In git? | Edit? |
|-------|------|---------|-------|
| Go source | `sgre/` | yes | yes |
| Extension source (skills, agent body, command instructions) | `extension/shared/` | yes | yes |
| Platform wrappers | `extension/opencode/`, `extension/claude-code/` | yes | yes (thin wrappers only) |
| Installed copies (Claude Code) | `.claude/` | **no** (`.gitignore`) | **never** — generated from `extension/shared/` + wrappers |
| Installed copies (OpenCode) | `.opencode/` | **no** (`.gitignore`) | **never** — generated |
| Scan output / DB | `.codeagent/` | **no** (`.gitignore`) | **never** — runtime artifact |
| Release output | `dist/` | **no** (`.gitignore`) | **never** — build artifact |

`.claude/`, `.opencode/`, `.codeagent/`, `dist/` are **generated / runtime
artifacts**. They are rebuilt from source by `release/build-packages.sh` (for
release zips) or `install.sh` (for local install). Editing them directly is
wasted work — the next install overwrites it.

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
- `extension/opencode/`, `extension/claude-code/` — thin wrappers (only the
  wrapper-specific parts; the `{{include shared/...}}` directives are expanded
  at build time)
- `release/` — build/install scripts
- Root docs (`README.md`, `CLAUDE.md`, `CHANGELOG.md`, `VERSION`)

If a finding is *only* reproducible in a dot-prefixed generated directory and
not in the source it was generated from, it is an **install-time issue**, not
a release blocker — note it and move on.

## Go Conventions

- **No comments unless asked** — the codebase is comment-light; match the
  surrounding style.
- **Error handling**: check errors at I/O and DB boundaries. Swallowing
  `err` with `_` is acceptable only for best-effort cleanup (`Close`,
  logging); never for `InsertEvent`/`InsertFinding`/`Build` — a swallowed
  write error causes silent false-negatives.
- **Build tags**: tests that call `OpenInMemory` / `NewTestStore` (which need
  the SQLite driver) must carry `//go:build !nosqlite`, so the `nosqlite`
  subset stays green.
- **CWE mapping**: `planner.VulnTypeSpec.CWE` is the single source of truth.
  Never hardcode a parallel CWE map in `report/`, `db/`, or `cli/`. The
  `db.SupportedFindingCWEs` default map is a test-only fallback; the live
  set is injected from `planner.AllCWEs()` at CLI startup.

## Versioning

- `VERSION` file at repo root holds the release version (e.g. `0.2.0`).
- `sgre/internal/cli/root.go` `var Version` is the Go-side fallback; release
  builds inject it via `-ldflags -X`.
- `sgre/internal/report/protocol.go` `var ToolVersion` is stamped into SARIF
  and markdown reports; `cli/root.go` sets `report.ToolVersion = Version` at
  startup so reports never carry a stale hardcoded version.
- `CHANGELOG.md` records per-release changes.

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

## See Also

- `CLAUDE.md` — full architecture, pipeline stages, data model, design invariants
- `docs/output-protocol.md` — scan output contract
- `DEVELOPER.md` — developer notes (currently empty)