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
1. Collect pointer variables (declared with `*`), counting pointer levels and the base type
2. Find `sizeof_expression` whose operand is a bare identifier that is a pointer variable
3. Require the sizeof to be consumed by a malloc-family / memset / memcpy-family call
4. Resolve the base type through typedefs (cross-file: `typedef char *cstr_t` in a header counts) to decide the category:
   - `sizeof_pointer` — **confirmed**: `sizeof(p)` on a single-level pointer `T *p` where `T` resolves to a non-pointer (`char *q`, `my_uint *p`). `sizeof(p)` is the pointer width while the call intends `sizeof(*p)` — the classic CWE-467 defect.
   - `sizeof_pointer_ambig` — **suspected**: `sizeof(p)` on a pointer-to-pointer (`T **p`) or a `T *p` whose `T` resolves to a pointer typedef (`cstr_t *s`). Allocating an array of pointers legitimately uses `sizeof(p)`, so it can only be suspected.
5. Emit `SIZEOF_MISUSE` otherwise

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `sizeof_pointer` (`char *q; malloc(n * sizeof(q))`) — pointer width where `sizeof(*q)` is meant | **confirmed** |
| `sizeof_pointer_ambig` (`char **p; malloc(n * sizeof(p))`) — may allocate pointer slots, or the base is a pointer typedef | **suspected** — reason over the actual intent |
| `memset(p, 0, sizeof(p))` where `p` is a pointer | **confirmed** (zeroes only a pointer width) |
| `malloc(n * sizeof(*p))` | **false-positive** (correct deref) |
| `malloc(n * sizeof(struct foo))` | **false-positive** (type, not pointer) |

### Common False Positives
- `sizeof(char*)` used intentionally (array of pointers)
- A macro that expands `sizeof(*p)` but is text-matched as `sizeof(p)`
