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

### Evidence Pattern
A path-traversal candidate has:
- **path_traversal**: A call to `fopen`/`open`/`openat`/`unlink`/`remove`/`rename`/`access`/`stat`/`lstat`/`opendir`/`chmod`/`chown`/`mkdir`/`rmdir` whose path argument is not a string literal
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Find calls to filesystem sinks
2. Extract the path argument (first argument; second for `openat`)
3. Skip if the path is a string literal
4. Emit `PATH_TRAVERSAL` otherwise

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `fopen(user_input, "r")` where input reaches the sink | **confirmed** |
| `open(config_path, ...)` — variable path of unknown origin | **suspected** |
| `fopen("/etc/config", "r")` — literal path | **false-positive** (safe) |
| `fopen(build_path(a, b), ...)` with a compile-time constant base | **suspected** |

### Common False Positives
- Literal or compile-time-constant paths (config file paths, fixed install locations)
- Paths built by trusted configuration, not user input
- This detector is source-agnostic (no taint tracking) — verify the source before confirming
