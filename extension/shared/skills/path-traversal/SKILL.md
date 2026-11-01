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
- **permission_setting**: a chmod/fchmod whose mode is other-writable (world_writable_file / world_writable_var — CWE-732, NOT a `../` traversal)
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
| `mode@<octal>` | permission_setting (CWE-732): the chmod/fchmod mode argument | the pipeline proved its other-write bit (0o002) is set |
| `path@<literal\|var>` | permission_setting: the chmod path shape | `literal` (non-temp fixed path) → **confirmed**; `var` (variable path/fd) → suspected (umask filtering cannot be proven) |

`path-arg@` names the argument the traversal rides on; `tainted` alongside
it means the segments come from outside — confirm unless a sanitizer is
visible in the Code Context. The `mode@`+`path@` pair is the separate
`permission_setting` category (CWE-732), judged independently of `path-arg@`.

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
| `fopen(path, ...)` — path is a parameter with no provable tainted caller and no census | **judge the function's exposure** — if it is a library / partial-scan export (zero in-tree callers, address-taken, an entry-point API), treat the parameter as an external ABI boundary and **confirm** the traversal risk; only an internal, provably-trusted parameter is **dismissed** |
| `fopen("/etc/config", "r")` — literal or compile-time-constant path | **false-positive** (safe) |
| `chmod("/etc/app.conf", 0666)` — `mode@` other-write on a non-temp `path@literal` | **confirmed** (CWE-732 world-writable file) |
| `chmod(path_var, 0666)` / `fchmod(fd, 0666)` — `mode@` other-write on `path@var` | **dismissed** unless you can prove the path is a non-temp fixed location (umask filtering is unprovable) |
| `chmod("/tmp/x", 0666)` — a temp-prefixed literal path | **false-positive** (the detector never emits it) |

The **confirmed** verdict applies when the pipeline proved a taint source
(`taint_source` evidence fragment), when `callsites@` names a non-constant
caller, or when the parameter is an external/exported ABI boundary with no
in-tree caller. Do NOT dismiss a parameter merely because the census is absent —
the census measures who passes what, never whether the value is trusted.

### Common False Positives
- Literal or compile-time-constant paths (config file paths, fixed install locations)
- A path parameter that is always called with a trusted constant — the `callsites@N:all-literal` census settles this from the row (the pipeline drops these before they reach you; if one slips through with the census, dismiss it)
- A path segment derived from `basename(p)` / `strrchr(p, '/')` — the result cannot contain a directory component, so it cannot carry `../`
- A `chmod` on a `/tmp`/`/var/tmp`/`/dev/shm` path — a temp file's permissions are not a meaningful privilege-setting defect (the detector suppresses it)
- A `chmod` mode that is not other-writable (`0644`, `0600`) — the detector only reports the other-write bit (0o002), never world-readable (0o004)

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
// 3. Canonicalize and confirm it stays inside BASE_DIR (note the '/' boundary:
//    a bare prefix compare would accept /srv/baseevil for BASE_DIR=/srv/base)
char resolved[PATH_MAX];
if (realpath(safe, resolved) == NULL) return -1;
size_t base_len = strlen(BASE_DIR);
if (strncmp(resolved, BASE_DIR, base_len) != 0 ||
    (resolved[base_len] != '\0' && resolved[base_len] != '/')) return -1;
// 4. Only now touch the filesystem
FILE *f = fopen(resolved, "r");
```

For write/delete sinks (`unlink`/`rename`/`chmod`), `realpath` fails on a
not-yet-created target, so anchor the directory instead and use
`openat(dfd, path, O_NOFOLLOW)` with the `dfd` from `open(BASE_DIR, O_DIRECTORY)`
— that removes the TOCTOU window and the prefix-bypass at once.
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
