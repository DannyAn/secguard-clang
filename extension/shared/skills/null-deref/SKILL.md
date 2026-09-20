---
name: null-deref
description: Classify null dereference evidence — NULL_VALUE source, DEREFERENCE event, NULL_GUARD counter-evidence. Maps to CWE-476.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-476
  severity: HIGH
  domain: memory
---

## Null Dereference Analysis (CWE-476)

`contract_kind: implicit` — a parameter dereferenced without a dominating null
check establishes an implicit non-null precondition (`ctx != NULL`). This skill
judges NULL **reachability, not null-check presence**: a bare `T *p` parameter
with no null check is **not** a finding by itself.

A NULL source reaches a parameter dereference when either (intra-procedural) the
function assigns NULL / a nullable allocator/return / an external call, or
(inter-procedural, `origin: caller_null`) a caller passes a value it has not
proven non-null for that parameter:

- a caller passes literal `NULL` / `0` → the parameter is nullable on that path;
- a caller passes an unguarded variable → NULL reachability is **unknown**;
- a caller whose early-return check (`if (v == NULL) return;`) dominates the call
  proves non-null, so it is filtered and does **not** surface.

The contract is **path-dependent**: a guarded caller does not rescue a function
that another caller violates. These surface as `suspected`, never auto-confirmed.

### Evidence Pattern
A null-deref candidate has:
- **nullable_source**: Variable has a NULL_VALUE origin (malloc return, function return NULL, external call, or a free+null macro `SAFE_FREE(p)` that sets `p = NULL`)
- **caller_null**: A `void *`/`T *` parameter is nullable because a caller passes it a value it has not proven non-null (`caller c passes NULL`, `caller c passes x (not proven non-null)`)
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
| External call return + no guard + deref | **dismissed** (external may never return NULL) |
| `caller_null` (parameter) + no guard + deref | **suspected** — the caller contract is unproven; confirm only if a caller actually passes NULL/unproven value |
| `caller_null` (parameter) + every caller proves non-null (`if (v == NULL) return;` dominates the call) | **false-positive** — the pipeline filters these before they surface |

### Common False Positives
- `if (ptr == NULL) return;` before `ptr->field` → guard eliminates risk
- `if (!ptr) { ... return; }` early return → guard eliminates risk for rest of function
- `ptr = malloc(n); if (!ptr) return; ptr->field;` → malloc checked

### Macro Context (Hint `macro-context`)
When the Hint carries `macro-context`, a function-like macro is in play and the
pipeline's null-flow proof may be wrong. Verify the macro before confirming:
- A NULL/error guard macro (`DBM_CHECK_RET(ctrl == NULL, FALSE)`, `CHECK_RET`,
  `ASSERT`, any `*CHECK*`/`*ASSERT*`/`*RET*` that early-returns) establishes the
  argument is non-null on the fall-through → **false-positive (dismissed)**.
- An iterator/accessor macro (`DBM_TAILQ_FIRST(...)`, `list_for_each_entry`,
  `rte_pktmbuf_mtod`) yields non-null by contract → **false-positive**.
- The macro definition is out of scan range and its contract is unclear →
  **dismissed** (never confirmed).

### Fix Suggestions
- Add NULL check before dereference: `if (ptr == NULL) { return -1; }`
- Use early return pattern: `if (!ptr) return;`
- For malloc: always check return before use
- For function returns: check API contract — does it document NULL return?

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Source | Guard | Severity |
|--------|-------|----------|
| malloc return | none, deref reachable | HIGH |
| function return NULL | none, deref reachable | HIGH |
| external call return | none (may never be NULL) | MEDIUM (dismissed) |
| any | partial guard (misses the deref) | MEDIUM (dismissed) |