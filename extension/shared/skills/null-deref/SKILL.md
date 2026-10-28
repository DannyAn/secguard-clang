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

### Evidence closure (read before any source read)

The candidate file already embeds the decisive cross-file facts the pipeline
resolved: an in-scan callee body under `## Callee Definition` (Hint
`callee@<file>:<line>`) and project macro bodies under `## Macro Definition`
(Hint `macro@<name>`). Read those sections first — they are in-file and cost no
lookup. Only a fact that is NOT embedded may be resolved with `secguard_def` /
`secguard def <symbol>` (batch related symbols); never grep the repository for a
definition, and never dismiss a macro/callee as "out of scan" before checking
the embedded section and the indexed lookup.

### Classification Rules

The confirmed/false-positive rows below apply ONLY to the one proven tier
(`null@cfg-proof` — a definite NULL assignment reaching the deref on every
path). Every other tier (`null@malloc-fail`, `null@caller-arg`,
`null@opaque-origin`, `null@assumed-return`, `null@external-unknown`) is a
**may-null heuristic**, never auto-confirmed — the Nullable-Origin Tier table
below rules them.

| Condition | Classification |
|-----------|---------------|
| `null@cfg-proof` + reachable + NO guard | **confirmed** |
| `null@cfg-proof` + guard BEFORE deref (scope covers) | **false-positive** |
| `null@cfg-proof` + guard AFTER deref (scope misses) | **confirmed** |
| Nullable source + NOT reachable | **false-positive** (dead code) |
| `null@malloc-fail` / `null@caller-arg` / `null@opaque-origin` / `null@assumed-return` / `null@external-unknown` (any guard state) | **suspected** — a may-null tier is NEVER confirmed from this table; judge it by the Nullable-Origin Tier table below |
| External call return + no guard + deref | **dismissed** (external may never return NULL) |
| `caller_null` (parameter) + no guard + deref | **suspected** — the caller contract is unproven; confirm only if a caller actually passes NULL/unproven value |
| `caller_null` (parameter) + every caller proves non-null (`if (v == NULL) return;` dominates the call) | **false-positive** — the pipeline filters these before they surface |

### Group verdict (large candidate sets)

Rows may share ONE verdict **only when `Function` + origin tier + `chain-root`
are all identical** (caller-arg / opaque-origin / array-buffer / external-unknown /
assumed-return + `guard@none`). They then answer ONE question: "can this
function's parameter / this object graph be NULL?" Decide the group once from
the highest-signal row (or the `## Location` signature), then reuse that
reasoning for the siblings with `group:<fn>:<tier>:<chain-root>: <why>` in each
reason. A `proc->profile` judged non-null by the function's entry contract also
dismisses `proc->ctx` for the same reason — re-deriving it per row is the
dominant cost of a 100+ candidate null-deref type, and it is what a
201-candidate zero-confirmed review looks like when it is done row by row.

**The `chain-root` dimension is NOT optional.** Two rows in the same function
with DIFFERENT `chain-root@` values (or one that carries `sibling-callers@`) are
NOT one group: a guard on one entry chain does not protect the sinks reached
through another. Grouping them together and reusing one chain's guard as the
whole group's dismissal is exactly the cross-chain misuse that dismissed a real
null-deref (a `count == 0` guard on the `proc_entry` chain was applied to the
`list_proc_callback` chain, which has no guard). Judge every distinct chain
independently and confirm when ANY chain reaches the sink unguarded.

### Common False Positives
- `if (ptr == NULL) return;` before `ptr->field` → guard eliminates risk
- `if (!ptr) { ... return; }` early return → guard eliminates risk for rest of function
- `ptr = malloc(n); if (!ptr) return; ptr->field;` → malloc checked
- `ptr = zmalloc(n); ptr->field;` → zmalloc aborts on OOM (never returns NULL) → **false-positive**; the same holds for any wrapper whose only `return NULL` is guarded by `zmalloc`/`zcalloc`/`xmalloc`/`oom()` (`listCreate`, `sdsnew`, ...) — the `return NULL` is dead code
- `while (p) { use(p); p = lpNext(lp, p); }` → `lpNext` returns NULL at end-of-list, but the NULL is consumed by the NEXT `while (p)` check, so `use(p)` is guarded → **false-positive**

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
| `null@malloc-fail` | the null source is a **may-null** call result (allocator / known maybe-null libc / a callee whose body has a NULL-return path: a literal NULL or an allocator result) — NOT a must-null proof | judge reachability, not just the shape: (1) does the callee actually return NULL, or does it abort-on-OOM (`zmalloc`/`xmalloc`/`oom()` never returns) making its `return NULL` dead code? (2) is the deref loop-guarded (`while(p)`) or otherwise checked? (3) can the NULL case actually occur for this call's arguments? Confirm only when the callee can really return NULL AND the deref is unguarded; otherwise dismiss. When the Hint carries `callee@file:line`, the callee body is embedded under `## Callee Definition`, judge it there instead of reading source |
| `null@caller-arg` | an inter-procedural caller passes the parameter unproven non-null | judge the caller contract — confirm only if a caller can actually pass NULL |
| `null@opaque-origin` | the null source is a contract the scan tree cannot see: a pointer parameter of a function with zero in-tree callers (an exported API / registered callback), or a field value of an externally-defined type (`tree = (T *)(resp->group_data)`, `para->orig->base_dn`) | a fail-open ASSUMPTION, not evidence — confirm when the external contract can plausibly yield NULL (an entry point that parses external input, a lookup that can miss), dismiss when the non-null precondition is an established project convention (an internal API whose other callers all pass non-null) |
| `array-buffer@<count-field>` | the null source is a count-gated array buffer: `tree = (T *)(resp->group_data)` whose validity is gated by the paired count field `resp->group_num` — `count == 0 ⇒ buffer is NULL/empty` | **convicting, not exculpating.** Confirm when the candidate's chain dereferences the buffer (`tree[0]`) without checking the count field; dismiss only when the SAME chain (`chain-root@`) checks the count (`count == 0` / `count > 0`) before the dereference. The count/data NAME pairing is a heuristic SIGNAL, not a proof — verify from the Code Context that the count field actually gates this buffer (same struct, matching stem) before confirming |
| `null@assumed-return` | an IN-SCAN callee graded maybe-null only by fail-open (it returns a parameter, a struct field, or an unknown call) — its body is embedded under `## Callee Definition` | judge the assumption from the embedded body — confirm only if the returned value can actually be NULL (a zero-initialized field, a nullable forward), otherwise dismiss |
| `null@external-unknown` | the ONLY null source is an unproven external call — a fail-open analyzer ASSUMPTION, not evidence | verify the callee can return NULL (API knowledge), otherwise dismiss |

`guard@none` in the same Hint means no same-function null guard precedes the
deref (machine-verified) — do not spend a read looking for one. It says nothing
about guards OUTSIDE the dereference's function, which is where most of these
false positives live:

### Cross-function guards and branch premises (stdlib `guard@none` traps)

The pipeline already models the two patterns below when the error constants are
literal `0`/`NULL`; it cannot model every project's spelling, so judge these
from the embedded callee body + the Code Context window:

1. **A check/validation callee that gates the dereference.** If `p` is passed to
   `check(p)` / `prepare(p)` and the caller bails on the callee's failure
   (`if (check(p) != OK) return;`), and that callee's entry does
   `if (p == NULL) return <error>`, then the surviving path has `p != NULL` —
   **dismiss**, citing the callee's guard line and the caller's gate line.
   The same holds when the status is first stored (`int ret = check(p); if (ret
   != OK) return;`) and when the constant is a symbol whose success value is 0
   (`NAT_OK`, `STMP_OK`). What does NOT prove anything: ignoring the result
   (`(void)check(p);`), gating on a NON-zero/other constant, or a callee that
   returns `0` on the null path.
2. **A branch premise that excludes the callee's NULL condition.** When the
   Hint carries `retnull-cond@<expr>`, the pipeline already extracted the ONE
   condition under which the callee returns NULL (its body is under `## Callee
   Definition`). Compare `<expr>` with the enclosing branch shown in the Code
   Context: if the call sits in the branch that EXCLUDES that condition (the
   `else` of `if (<expr>)`, or after an early-return on `<expr>`), the NULL path
   is unreachable here. If the callee returns NULL only when `obj->field == C`
   and the call is in the `else` of `if (obj->field == C)`, dismiss. The premise survives only
   while nothing rewrites `obj->field` between the branch entry and the call —
   judge the interval from the Code Context: a read-only statement, or an
   intervening call that takes the object as `const` / is a pure lookup
   (a `find_*`/`get_*` whose body shows no write to the field) keeps it.
   A call that mutates the object (`*_set_*`, `*_update_*`, a body that assigns
   the field) defeats it: keep the finding and name the call.

Never dismiss on "there is some null check somewhere": the check must dominate
the dereference on the surviving path.

### Multiple caller chains (Hint `chain-root@` / `sibling-callers@`)

A function can be reached through SEVERAL independent chains — a direct call AND
a function-pointer / callback registration that invokes the same function. When
the Hint carries `chain-root@<fn>` and `sibling-callers@<fn1,fn2>`, the candidate
was found on `<fn>`'s chain and the function is ALSO called from the siblings.

**A guard on a sibling chain's path does NOT dismiss this candidate.** Judge
EVERY caller chain independently and confirm when ANY chain reaches the sink
without a dominating guard. The classic failure: the Evidence shows
`call chain: a → f` (no guard) while a sibling caller `b` checks a field before
calling `f`; citing `b`'s guard is not evidence, because `a`'s path never passes
through `b`. When `sibling-callers@` is present, say which chain is guarded and
which is not; confirm if any is unguarded.

### count/data field pairs (partial-contract traps)

An external message struct often pairs a `count` field with a `data` pointer:
`data` is valid only while `count > 0`. That contract is **convicting, not
exculpating** — it means `count == 0 ⇒ data` is NULL/invalid, so any path that
dereferences `data[...]` without checking `count` is a real NULL dereference.

- Dismiss only when the SAME chain (the candidate's `chain-root@` path) checks
  `count` (a `count == 0` / `count > 0` guard, or a `count*sizeof(T) == len`
  validation) BEFORE the dereference.
- A quote like "data valid whenever count>0" must be read as "count==0 ⇒ data
  invalid": if the candidate's chain never tests `count`, confirm and cite the
  unchecked dereference.
- Do NOT dismiss with "framework contract" alone — the contract is exactly what
  makes the unchecked dereference a defect.
- **A dispatch/framework non-null contract marks the parameter ITSELF, never its
  fields.** "`resp` is non-null by the NAC msg dispatch contract" can only
  dismiss a dereference of `resp` itself; it says NOTHING about `resp->group_data`
  (a count-gated array buffer whose validity depends on `group_num`) or
  `resp->hdr->data` (an internal pointer field). For a `resp->field` candidate,
  the dismissal must cite the FIELD's own assignment/validation point; citing the
  callback parameter's dispatch contract is an over-reach and is not accepted.

### Macro Context (Hint `macro-context`)
When the Hint carries `macro-context`, a function-like macro is in play and the
pipeline's null-flow proof may be wrong. Verify the macro before confirming:
- A NULL/error guard macro (`DBM_CHECK_RET(ctrl == NULL, FALSE)`, `CHECK_RET`,
  `ASSERT`, any `*CHECK*`/`*ASSERT*`/`*RET*` that early-returns) establishes the
  argument is non-null on the fall-through → **false-positive (dismissed)**.
- An iterator/accessor macro (`DBM_TAILQ_FIRST(...)`, `list_for_each_entry`,
  `rte_pktmbuf_mtod`) yields non-null by contract → **false-positive**.
- The macro is not embedded under `## Macro Definition` and `secguard def
  <MACRO>` returns no in-tree definition, so its contract is genuinely unknown →
  **dismissed** (never confirmed). If the body IS embedded, judge the expansion
  — do not dismiss merely because the call site looks opaque.

### Fix Suggestions
- Add NULL check before dereference: `if (ptr == NULL) { return -1; }`
- Use early return pattern: `if (!ptr) return;`
- For malloc: always check return before use
- For function returns: check API contract — does it document NULL return?
- When the Evidence section notes `the same nullable X is also dereferenced at line(s) N, M`, the candidate covers EVERY sink of that variable — the fix must guard all of them, not just the reported line.

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