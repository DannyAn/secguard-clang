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
- **definite_null**: The variable is provably NULL — assigned NULL (or a null constant) and dereferenced with no intervening reassignment. The strongest evidence tier; the pipeline has already auto-confirmed these, so a candidate reaching you with this fragment needs verification, not re-derivation
- **nullable_source**: Variable has a NULL_VALUE origin (malloc return, function return NULL, external call, or a free+null macro `SAFE_FREE(p)` that sets `p = NULL`)
- **caller_null**: A `void *`/`T *` parameter is nullable because a caller passes it a value it has not proven non-null (`caller c passes NULL`, `caller c passes x (not proven non-null)`)
- **call_path**: The function is reachable from an entry point
- **data_flow**: The NULL value propagates to the dereference location
- **weak_guard**: A NULL guard exists but is insufficient (scope misses the deref, or only partially protects) — the pipeline kept the candidate because the guard does NOT dominate the dereference; verify the guard's scope before dismissing
- **dereference**: Bare fallback fragment — only the deref itself is known (no null source, no flow proof). Judge reachability and nullability yourself from the source

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

### Short-Circuit & Interprocedural Guard Contracts

Three guard shapes the pipeline recognizes and dismisses automatically; when
one of these reaches you anyway (e.g. under the `assumed-return` or
`caller-arg` tier), apply the same reasoning before confirming:

- **Short-circuit guard line** (callee side): a dereference ON the guard
  condition line (`p == NULL || !p->is_used`, `p == NULL || p[0] == '\0'`) is
  protected by short-circuit evaluation — the right operand only evaluates
  when `p` is non-null → **false-positive**.
- **Conditional-nonnull getter** (callee contract): the callee returns NULL
  only under a null check of a pointer parameter (`if (c == NULL) return
  NULL; return &c->addr;`) and the call site sits inside the argument's own
  null guard → the callee cannot return NULL for these arguments →
  **false-positive**. A getter whose NULL path depends on anything else (an
  id range check `id >= MAX`, global state `!g_loaded`) does NOT carry this
  contract — judge it on its own NULL paths.
- **Guard-mutex strip helper** (callee contract + caller guard): the callee
  returns NULL only under a parameter null check or a `strlen(p) >= len`
  overflow check, and the caller early-returns under the conjunctive guard
  `strlen(arg) != 0 && lhs == NULL` — an overflow implies
  `strlen(arg) >= len > 0`, so the guard fires before the dereference →
  **false-positive**. The length argument must be provably positive
  (sizeof / positive literal) for the mutex to hold.

### Nullable-Origin Tier (Hint null@ tokens)

The Hint's first null token states HOW the pipeline knows the value can be null —
your job differs per tier, so read it before anything else:

| Tier token | Meaning | Your action |
|------------|---------|-------------|
| `null@cfg-proof` | CFG proves a NULL assignment reaches the dereference on every path | machine-proved CWE-476 — verify the statement matches, then confirm |
| `null@malloc-fail` | the null source is a proven-nullable call result (allocator / known maybe-null libc / a callee whose body PROVABLY returns NULL: a literal NULL path or an allocator result) | textbook CWE-476 — confirm unless the `## Code Context` shows a check; when the Hint also carries `callee@file:line`, the callee body is embedded under `## Callee Definition`, judge it there instead of reading source |
| `null@caller-arg` | an inter-procedural caller passes the parameter unproven non-null | judge the caller contract — confirm only if a caller can actually pass NULL |
| `null@opaque-origin` | the null source is a contract the scan tree cannot see: a pointer parameter of a function with zero in-tree callers (an exported API / registered callback), or a field value of an externally-defined type (`tree = (T *)(resp->group_data)`, `para->orig->base_dn`) | a fail-open ASSUMPTION, not evidence — confirm when the external contract can plausibly yield NULL (an entry point that parses external input, a lookup that can miss), dismiss when the non-null precondition is an established project convention (an internal API whose other callers all pass non-null) |
| `null@assumed-return` | an IN-SCAN callee graded maybe-null only by fail-open (it returns a parameter, a struct field, or an unknown call) — its body is embedded under `## Callee Definition` | judge the assumption from the embedded body — confirm only if the returned value can actually be NULL (a zero-initialized field, a nullable forward), otherwise dismiss |
| `null@external-unknown` | the ONLY null source is an unproven external call — a fail-open analyzer ASSUMPTION, not evidence | verify the callee can return NULL (API knowledge), otherwise dismiss |

`guard@none` in the same Hint means no same-function null guard precedes the
deref (machine-verified) — do not spend a read looking for one.

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