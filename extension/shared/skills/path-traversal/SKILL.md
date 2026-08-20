---
name: path-traversal
description: Classify path-traversal evidence — a filesystem sink receiving a non-literal path argument. Maps to CWE-22.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-22
  severity: HIGH
---

## Path Traversal Analysis (CWE-22)

**What this is:** a filesystem call (`fopen`/`open`/`openat`/`opendir`/
`unlink`/`remove`/`rename`) receives a path that is **not a fixed string
literal**. If an attacker can control that path, they can use `../` to escape
the intended directory and read / overwrite / delete an arbitrary file.

### Evidence Pattern
A path-traversal candidate has:
- **path_traversal**: a filesystem sink whose path argument is not a string literal
- **call_path**: the function is reachable from an entry point
- **taint_source** (when the pipeline proved it): a user-controlled value
  (getenv / argv / recv / scanf / fgets …) reaches the path argument

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `fopen(user_input, "r")` where a taint source reaches the path | **confirmed** |
| `fopen(path, ...)` where `path` is a function parameter with no provable tainted caller | **suspected** |
| `fopen("/etc/config", "r")` — literal or compile-time-constant path | **false-positive** (safe) |

The **confirmed** verdict only applies when the pipeline proved a taint source
(`taint_source` evidence fragment). A parameter of unknown origin stays
**suspected** — do not promote it without tracing a caller that passes
attacker-controlled data.

### Common False Positives
- Literal or compile-time-constant paths (config file paths, fixed install locations)
- A path parameter that is always called with a trusted constant (trace the callers)

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
