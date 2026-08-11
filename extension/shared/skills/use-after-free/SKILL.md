---
name: use-after-free
description: Classify use-after-free evidence — free() followed by dereference or use. Maps to CWE-416.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-416
  severity: CRITICAL
---

## Use-After-Free Analysis (CWE-416)

### Evidence Pattern
A use-after-free candidate has:
- **use_after_free**: Variable was freed (free() call) then subsequently used (dereference, passed to function, or accessed via pointer)
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Find all `free(ptr)` calls in a function — record variable name and line
2. Find all subsequent uses of `ptr` (pointer dereference `*ptr`, field access `ptr->field`, or passing to function)
3. If use line > free line, emit USE_AFTER_FREE event

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| free + use after free in same function, no re-alloc | **confirmed** |
| free + use, but variable reassigned between free and use | **false-positive** |
| free in one branch, use in another mutually exclusive branch | **false-positive** |
| free + use in different functions (interprocedural) | **suspected** (needs data flow) |

### Common False Positives
- `free(ptr); ptr = NULL; ptr->field;` — crash, not UAF (NULL deref instead)
- `free(ptr); ptr = malloc(...); ptr->field;` — re-allocation before use
- `if (cond) { free(ptr); } ... if (!cond) { ptr->field; }` — mutually exclusive branches

### Fix Suggestions
- Set pointer to NULL after free: `free(ptr); ptr = NULL;`
- Use a wrapper that nulls the pointer: `#define SAFE_FREE(p) do { free(p); p = NULL; } while(0)`
- Avoid using the freed pointer — restructure code to move use before free
- Consider using use-after-free sanitizers (ASan) during testing

### Severity Matrix
| Pattern | Severity |
|---------|----------|
| free + dereference | CRITICAL |
| free + pass to function | HIGH |
| free + use in different function | HIGH (suspected) |