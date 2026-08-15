---
name: sizeof-misuse
description: Classify sizeof-misuse evidence — sizeof applied to a pointer variable inside a size context. Maps to CWE-467/CWE-468.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-467
  severity: HIGH
---

## sizeof Misuse Analysis (CWE-467 / CWE-468)

### Evidence Pattern
A sizeof-misuse candidate has:
- **sizeof_misuse**: A `sizeof(ptr)` where `ptr` is a pointer VARIABLE (not `sizeof(*ptr)`, not `sizeof(T)`) consumed as a size argument to `malloc`/`calloc`/`realloc`/`memset`/`memcpy`/`memmove`
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Collect pointer variables (declared with `*`)
2. Find `sizeof_expression` whose operand is a bare identifier that is a pointer variable
3. Require the sizeof to be consumed by a malloc-family / memset / memcpy-family call
4. Emit `SIZEOF_MISUSE` otherwise

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `char **p; malloc(n * sizeof(p))` — allocates n pointer slots, not n `char` | **confirmed** |
| `memset(p, 0, sizeof(p))` where `p` is a pointer | **confirmed** (zeroes only a pointer width) |
| `malloc(n * sizeof(*p))` | **false-positive** (correct deref) |
| `malloc(n * sizeof(struct foo))` | **false-positive** (type, not pointer) |

### Common False Positives
- `sizeof(char*)` used intentionally (array of pointers)
- A macro that expands `sizeof(*p)` but is text-matched as `sizeof(p)`
