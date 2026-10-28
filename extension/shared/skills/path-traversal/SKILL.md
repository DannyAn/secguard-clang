---
name: path-traversal
description: Classify path-traversal evidence — a filesystem sink receiving a non-literal path argument. Maps to CWE-22.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-22
  severity: HIGH
  domain: security
---

## Path Traversal Analysis (CWE-22)

**What this is:** a filesystem call (`fopen`/`open`/`openat`/`opendir`/
`unlink`/`remove`/`rename`) receives a path that is **not a fixed string
literal**. If an attacker can control that path, they can use `../` to escape
the intended directory and read / overwrite / delete an arbitrary file.

### Evidence Pattern
A path-traversal candidate has:
- **path_traversal**: a filesystem sink whose path argument is not a string literal
- **path_arg**: the path argument expression of the sink call
- **call_path**: the function is reachable from an entry point
- **taint_source** (when the pipeline proved it): a user-controlled value
  (getenv / argv / recv / scanf / fgets …) reaches the path argument
- **callsite_census** (when the path argument is a function parameter): the
  in-tree call-site argument census for that parameter — `all-literal` means
  every caller passes a compile-time constant
- **callsite_list** (when the argument is a function parameter): the concrete
  in-tree call sites (`literal`/`variable`/`tainted` @ file:line, bounded) — the
  non-constant callers to inspect, no grep needed

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `path-arg@<expr>` | the path argument expression — the traversal root | judge whether a caller can inject `../` segments; pair with `callsites@` when the argument is a parameter |
| `callsites@<census>` | the in-tree call-site census for the path parameter | `N:all-literal` = every in-tree caller passes a compile-time constant → **dismissed**; `N:K-literal,J-var` = the var/tainted callers are where attacker input could enter → inspect those callers before confirming; token absent = no in-tree call site binds the parameter (an external TU may call it) |

`path-arg@` names the argument the traversal rides on; `tainted` alongside
it means the segments come from outside — confirm unless a sanitizer is
visible in the Code Context.

### Evidence closure (read before any source read)

The candidate file already embeds the decisive cross-file facts the pipeline
resolved: an in-scan callee body under `## Callee Definition` (Hint
`callee@<file>:<line>`) and project macro bodies under `## Macro Definition`
(Hint `macro@<name>`). Read those sections first — they are in-file and cost no
lookup. Only a fact that is NOT embedded may be resolved with `secguard_def` /
`secguard def <symbol>` (batch related symbols); never grep the repository for a
definition, and never dismiss a macro/callee as "out of scan" before checking
the embedded section and the indexed lookup.

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `fopen(user_input, "r")` where a taint source reaches the path | **confirmed** |
| `fopen(path, ...)` — path is a parameter, `callsites@` shows a non-constant caller | **confirmed** (attacker-reachable via that caller) |
| `fopen(path, ...)` — path is a parameter, `callsites@N:all-literal` | **dismissed** (every in-tree caller passes a compile-time constant) |
| `fopen(path, ...)` — path is a parameter with no provable tainted caller and no census | **dismissed** |
| `fopen("/etc/config", "r")` — literal or compile-time-constant path | **false-positive** (safe) |

The **confirmed** verdict only applies when the pipeline proved a taint source
(`taint_source` evidence fragment) or `callsites@` names a non-constant caller.
A parameter of unknown origin stays **dismissed** — do not promote it without
tracing a caller that passes attacker-controlled data.

### Common False Positives
- Literal or compile-time-constant paths (config file paths, fixed install locations)
- A path parameter that is always called with a trusted constant — the `callsites@N:all-literal` census settles this from the row (the pipeline drops these before they reach you; if one slips through with the census, dismiss it)
- A path segment derived from `basename(p)` / `strrchr(p, '/')` — the result cannot contain a directory component, so it cannot carry `../`

### Fix Suggestions

Give the developer a concrete, copy-pasteable check — the canonical anti-
traversal pattern is: **reject `..`/absolute paths → resolve with `realpath` →
verify the result stays inside the allowed base directory**:

```c
// 1. Reject absolute paths and any '..' component
if (path[0] == '/' || strstr(path, "..") != NULL) return -1;
// 2. Build under a fixed base directory
char safe[PATH_MAX];
snprintf(safe, sizeof(safe), "%s/%s", BASE_DIR, path);
// 3. Canonicalize and confirm it stays inside BASE_DIR
char resolved[PATH_MAX];
if (realpath(safe, resolved) == NULL) return -1;
if (strncmp(resolved, BASE_DIR, strlen(BASE_DIR)) != 0) return -1;
// 4. Only now touch the filesystem
FILE *f = fopen(resolved, "r");
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Tainted path reaches a write/delete sink (`unlink`/`remove`/`rename`) | CRITICAL |
| Tainted path reaches a read sink (`fopen`/`open`/`opendir`) | HIGH |
| Path parameter with no provable tainted caller | MEDIUM (dismissed) |
