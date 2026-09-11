---
name: uninit
description: Classify uninitialized variable evidence — VALUE_USE events where a local variable is read before any assignment on some execution path. Maps to CWE-457.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-457
  severity: MEDIUM
---

## Uninitialized Variable Analysis (CWE-457)

### Evidence Pattern
An uninit candidate has:
- **uninit_use**: A local variable or struct field is read before any assignment
- **declaration** / **allocation**: Where the variable is declared (or heap-allocated and left uninitialized)
- **call_path**: The function is reachable from an entry point

### Detection Signals
- Local variable declared without initializer: `int x;`
- Used before first assignment: `return x;` or `arr[x]` or `if (x > 0)`
- Struct fields used before initialization

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Variable read before any assignment on ALL paths | **confirmed** |
| Variable may be initialized on some paths but not all (conditional init) | **suspected** |
| Variable initialized before use on all paths | **false-positive** |
| Compiler enforces initialization | **false-positive** |

### Common False Positives
- Variable initialized via pointer (out-parameter): `init(&x)`
- Variable initialized via `memset(&x, 0, sizeof(x))`
- Variable is a struct with default-zero semantics
- Static variables (zero-initialized by C standard)

### Fix Suggestions
- Initialize at declaration: `int x = 0;`
- Initialize on every branch: `if (c) { x = a; } else { x = b; }`
- Zero a struct before use: `memset(&s, 0, sizeof(s));`
- Prefer `calloc` over `malloc` for a buffer that is read before a full write

### Severity Matrix
| Initialization shape | Severity |
|----------------------|----------|
| Uninitialized on all paths | HIGH |
| Conditionally initialized (some paths) | MEDIUM (suspected) |
