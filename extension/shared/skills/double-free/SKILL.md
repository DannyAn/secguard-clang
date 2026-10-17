---
name: double-free
description: Classify double-free evidence — same variable freed twice. Maps to CWE-415.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-415
  severity: CRITICAL
  domain: memory
---

## Double-Free Analysis (CWE-415)

### Evidence Pattern
A double-free candidate has:
- **double_free**: the same object is released twice — either passed to `free()` two or more times in one function, or released by a helper and then freed again through the global slot that still holds it
- **first_free** / **second_free**: the first and second `free()`/release lines (for a global-slot case the first line is the release-helper call in the caller and `victims` names the stored objects)
- **may_free**: the first release is CONDITIONAL — the release helper frees only when its own condition holds (`if (ref_count <= 0) free(p)`). The candidate is a possible double free, never a must-proof.
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Find all frees in a function — `free(ptr)`, `free(p->field)` (field free), `free(arr[0])` / `free(arr[i])` (subscript free), and a freeing function-like macro (`#define my_free(p) free(p)`).
2. Group by variable name, and by field for field frees (so `free(p->msg)` twice is a double-free of `p->msg`, but `free(p->msg)` then `free(p->mode)` is two different objects).
3. If a variable (or field) appears in 2+ frees, emit DOUBLE_FREE for each subsequent free.
4. **Interprocedural global slot**: a function that frees a global array element (`free(g_items[i])`) has a release-effect summary for that global; a caller that stored an object into the slot and already released it via a release helper gets a second-free event at the cleanup CALL SITE. When the release helper frees the object only on some paths, the event carries `may_free`.
4. A macro that also nulls its argument (`SAFE_FREE(p)`) is NOT a double-free source — after it the pointer is NULL, so a later `free(p)` is `free(NULL)`, a no-op.

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Same variable freed twice unconditionally | **confirmed** |
| Freed in different branches of same if/else | **false-positive** (mutually exclusive) |
| Freed twice but reassigned between frees | **false-positive** |
| Same object released by a helper, then freed again through the global slot that still holds it (both releases run on one path) | **confirmed** |
| Same as above but `may_free` is set (the helper frees only on some paths) | **confirmed only if the two releases can both run on one path; otherwise dismissed** — the candidate is a possible, not a proved, double free |
| Two independent frees of a variable in DIFFERENT functions with no shared owner/slot | **dismissed** (interprocedural, different objects) |

### Common False Positives
- `if (a) free(ptr); ... if (!a) free(ptr);` — mutually exclusive conditions
- `free(ptr); ptr = malloc(...); ... free(ptr);` — re-allocated between frees
- `free(ptr); ptr = NULL; ... free(ptr);` — free(NULL) is a no-op
- A cleanup routine that frees every global slot, called BEFORE a release helper (nothing was released yet) — check the call ORDER, not just the call presence
- `may_free` where the helper's condition and the cleanup are mutually exclusive (e.g. the helper's error path returns before the cleanup)

### Fix Suggestions
- Set pointer to NULL after free: `free(ptr); ptr = NULL;`
- Use a safe free macro: `#define SAFE_FREE(p) do { free(p); p = NULL; } while(0)`
- Track ownership explicitly — only one code path should own the free
- Use RAII patterns where available

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Unconditional double free | CRITICAL |
| Conditional double free (same condition) | CRITICAL |
| Same object released by a helper, then freed again through its global slot | HIGH (confirmed when both releases can run; `may-free` → judge) |
| Two independent frees in different functions with no shared owner/slot | LOW (dismissed — different objects) |
| Conditional double free (mutually exclusive branches) | LOW (likely false positive) |