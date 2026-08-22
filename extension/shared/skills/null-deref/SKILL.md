---
name: null-deref
description: Classify null dereference evidence — NULL_VALUE source, DEREFERENCE event, NULL_GUARD counter-evidence. Maps to CWE-476.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-476
  severity: HIGH
---

## Null Dereference Analysis (CWE-476)

### Evidence Pattern
A null-deref candidate has:
- **nullable_source**: Variable has a NULL_VALUE origin (malloc return, function return NULL, external call, or a free+null macro `SAFE_FREE(p)` that sets `p = NULL`)
- **call_path**: The function is reachable from an entry point
- **data_flow**: The NULL value propagates to the dereference location
- **guard**: A NULL_GUARD event may or may not exist

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Nullable source + reachable + data flow + NO guard | **confirmed** |
| Nullable source + reachable + data flow + guard BEFORE deref (scope covers) | **false-positive** |
| Nullable source + reachable + data flow + guard AFTER deref (scope misses) | **confirmed** |
| Nullable source + NOT reachable | **false-positive** (dead code) |
| External call return + no guard + deref | **suspected** (external may never return NULL) |

### Common False Positives
- `if (ptr == NULL) return;` before `ptr->field` → guard eliminates risk
- `if (!ptr) { ... return; }` early return → guard eliminates risk for rest of function
- `ptr = malloc(n); if (!ptr) return; ptr->field;` → malloc checked

### Fix Suggestions
- Add NULL check before dereference: `if (ptr == NULL) { return -1; }`
- Use early return pattern: `if (!ptr) return;`
- For malloc: always check return before use
- For function returns: check API contract — does it document NULL return?

### Severity Matrix
| Source | Guard | Severity |
|--------|-------|----------|
| malloc | none | HIGH |
| function return | none | HIGH |
| external call | none | MEDIUM |
| any | partial | MEDIUM (suspected) |