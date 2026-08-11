---
name: double-free
description: Classify double-free evidence — same variable freed twice. Maps to CWE-415.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-415
  severity: CRITICAL
---

## Double-Free Analysis (CWE-415)

### Evidence Pattern
A double-free candidate has:
- **double_free**: Variable is passed to `free()` two or more times in the same function
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Find all `free(ptr)` calls in a function
2. Group by variable name
3. If a variable appears in 2+ free() calls, emit DOUBLE_FREE event for each subsequent free

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Same variable freed twice unconditionally | **confirmed** |
| Freed in different branches of same if/else | **false-positive** (mutually exclusive) |
| Freed twice but reassigned between frees | **false-positive** |
| Freed in different functions | **suspected** (interprocedural) |

### Common False Positives
- `if (a) free(ptr); ... if (!a) free(ptr);` — mutually exclusive conditions
- `free(ptr); ptr = malloc(...); ... free(ptr);` — re-allocated between frees
- `free(ptr); ptr = NULL; ... free(ptr);` — free(NULL) is a no-op

### Fix Suggestions
- Set pointer to NULL after free: `free(ptr); ptr = NULL;`
- Use a safe free macro: `#define SAFE_FREE(p) do { free(p); p = NULL; } while(0)`
- Track ownership explicitly — only one code path should own the free
- Use RAII patterns where available

### Severity Matrix
| Pattern | Severity |
|---------|----------|
| Unconditional double free | CRITICAL |
| Conditional double free (same condition) | CRITICAL |
| Conditional double free (different branches) | LOW (likely false positive) |