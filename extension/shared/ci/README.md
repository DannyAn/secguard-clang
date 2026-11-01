# SecGuard CI Templates

PR/MR-level security review templates for SecGuard-Clang. These are **delivered
with the release package** (`extension/shared/ci/`) and are **not auto-installed**
into a user repository — copy the one you need into your own CI config.

## Placement

- GitHub: copy `github-pr.yml` to `.github/workflows/secguard.yml` (or merge its
  job into your existing workflow).
- GitLab: copy `gitlab-mr.yml` to `.gitlab-ci.yml` (or merge its job).

## secguard.toml

The templates assume a `secguard.toml` next to your CI config (the project root).
SecGuard reads it from `<cwd>/.codeagent/secguard.toml`; if you keep the config
elsewhere, pass `--config <path>` explicitly in the template. Do NOT put
`secguard.toml` in a directory that is not `.codeagent/` — the runtime data dir
uses `.codeagent/` naming, and a config in the wrong place silently disables
every detector setting.

## Threshold policy

`github-pr.yml` uploads SARIF via `github/codeql-action/upload-sarif` so findings
surface in the Code Scanning UI without failing the build. To gate the PR, set a
threshold in the workflow (see the `# Gate` comment) — a nonzero exit on new
critical/high findings is the recommended starting policy, tightened as your
team triages the backlog.

## Incremental review

The templates run the incremental review path (`secguard pr` / `secguard mr`)
against `base..head`. Re-running the same diff is idempotent (the review anchor
is derived from the base/head SHAs); a new head commit produces a new review.
