---
name: unchecked-return
description: Classify unchecked-return evidence — an allocation/I/O call whose return value is neither compared nor stored into a checked variable. Maps to CWE-252.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-252
  severity: HIGH
---

## Unchecked Return Value Analysis (CWE-252)

### Evidence Pattern
An unchecked-return candidate has:
- **unchecked_return**: A call to `malloc`/`calloc`/`realloc`/`fopen`/`opendir`/`read`/`recv`/`write`/`send` whose value is not compared directly and is not assigned to a variable that is later compared
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Find calls to the target allocation/I/O functions
2. Skip if the call is directly inside a comparison, `!` negation, or branch/loop condition
3. Skip if the result is assigned to a variable that appears in a `==`/`!=`/`<`/`>` comparison anywhere in the function
4. Emit `UNCHECKED_RETURN` otherwise

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `malloc(n)` result dereferenced with no NULL check | **confirmed** |
| `read(fd, ...)` return ignored and buffer used | **suspected** |
| `p = malloc(n); if (!p) return;` | **false-positive** (checked) |
| `if (malloc(n) == NULL) ...` | **false-positive** (checked inline) |

### Common False Positives
- Assignment followed by a check in a macro or helper (`xmalloc` wrappers)
- `read()` used where a short read is acceptable (e.g. `read(fd, &ch, 1)` loops)
