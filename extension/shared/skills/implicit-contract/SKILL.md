---
name: implicit-contract
description: Classify implicit-contract evidence — a caller/framework-supplied struct field is dereferenced with no dominating null guard, but the code null-checks the field elsewhere. Maps to CWE-20.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-20
  severity: MEDIUM
  domain: contract
---

## Implicit Contract — Missing Entry Validation Analysis (CWE-20)

`contract_kind: implicit` — the field's nullness is **open-world** (supplied by a
caller or a framework the scanner cannot see), not statically provable. The
pipeline deliberately **never auto-confirms** this type: it only surfaces a
candidate when the code itself treats the field as nullable (it null-checks the
field on another path) but fails to guard THIS dereference. You judge the
business contract, not a data-flow proof.

A confirmed finding here is a **null-deref in spirit (CWE-476-equivalent)** when
the empty/unusual path can actually occur; it is reported under CWE-20 because
the root cause is *missing validation of input state*, and the field's nullness
is a contract, not a proven source.

### Evidence Pattern
An implicit-contract candidate has:
- **contract_gap**: a pointer field `obj->P` (of struct parameter `obj`) is
  dereferenced at `use_line` with no dominating null guard.
- **missing**: the absent precondition (`obj->P != NULL`).
- **contract_evidence** (one of):
  - `sibling` — another function in the SAME FILE with the SAME parameter struct
    type null-checks the field (including a null check on a local derived from
    it, `tree = resp->group_data; if (tree == NULL)`). This is the only kept
    tier: the same-TU comparison makes the missing guard an omission;
  - `self` — only this function null-checks `obj->P` somewhere and the guard
    does not dominate the deref. This is a scope-gap hypothesis with no sibling
    reference and is pre-dismissed by the planner;
  - `sibling-weak` — a type-anchored guard in ANOTHER file only. Unrelated-TU
    evidence; pre-dismissed by the planner.
  - (caller validation is a *suppression*: if every caller null-checks the field
    before the call, the candidate is dropped, not surfaced).
- **count_field** (optional): when a count/length field `obj->N` gates the use
  (loop bound / subscript index), it is recorded as extra context — the pointer
  is a counted collection. It is NOT required: the pointer-null condition is
  caught independently of any count relationship.
- **shape_cluster** (only when shape-level clustering ran): the same unguarded
  field shape (field + access form + evidence tier + guard structure) repeats at
  other sites in the same file; this one candidate covers all of them, and
  `## Clustered Sites` lists them as `function:line`.
- **call_path**: the function is reachable from an entry point.

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `subject@<name>` | the struct-pointer parameter the contract is about | the entity to validate |
| `count-field@<name>` | the count/length field gating the pointer use | the contract the function actually enforces |
| `evidence-kind@sibling` | a SAME-FILE function with the same parameter struct type null-checks the field (the kept tier) | the same-TU comparison says the field MAY be nullable; judge whether NULL can reach THIS deref — a deref inside the same if-body / `&&` chain as the sibling's test is still a false-positive |
| `evidence-kind@self` | only this function checks the field, and its guard does not dominate the deref | non-proving scope-gap hypothesis — pre-dismissed by the planner; if it reaches you, confirm only from a cited reachable path |
| `evidence-kind@sibling-weak` | only ANOTHER file's function with the same parameter struct type null-checks the field | unrelated-TU evidence — pre-dismissed; never confirm on this alone |
| `sibling-guard@<fn>:<line>` | the same-file sibling `fn` null-checks the same field at that line | read that guard and compare its condition with this deref's Code Context |
| `self-guard@N` | the field IS null-checked at line N, but the reported deref sits OUTSIDE that guard's scope | the scope gap is the defect — confirm only if the deref is genuinely reachable outside the guard; a deref inside the same if-body / `&&` chain as the test is **false-positive** |
| `shape-cluster@N` | N other sites in the same file repeat this exact defect shape (same field, same access form, same evidence tier, same guard structure); they are listed under `## Clustered Sites` | judge the shape ONCE — the verdict covers every listed `function:line`; do not ask for a per-site verdict |

`subject@` + `count-field@` name the enforced contract; the verdict is
whether relying on it (without asserting the precondition) is a real gap.

### Detection Logic
1. Identify struct-pointer parameters whose fields are **read but never written**
   in the function (a field written in-scope belongs to null-deref, not here).
2. Find a pointer field `obj->P` that is dereferenced (directly or via a local
   `p = obj->P`).
3. Require nullable-field evidence: a null check of the field (or a local
   derived from it) in a same-file sibling function (kept), only in this
   function (self, pre-dismissed), or only in another file (sibling-weak,
   pre-dismissed). Without any evidence, the field is treated non-null by
   convention and no candidate is emitted.
4. Emit one `CONTRACT_GAP` (`category: ptr_guard`) per dereference site. The
   planner filter drops a site when that null-check **dominates** it on the CFG
   (properly guarded): an early-exit guard (`if (obj->P == NULL) return;`), a
   **same-block guard** (the deref sits inside the `if (obj->P != NULL)` body or
   the `else` of `if (obj->P == NULL)`), a short-circuited `&&` operand, or a
   loop condition. Only the unguarded sites survive as `suspected`.
5. Shape-level clustering folds the surviving sites that share a file, field,
   access form, evidence tier and guard structure into ONE representative (Hint
   `shape-cluster@N`, sites under `## Clustered Sites`), so the family is judged
   once instead of once per function.

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

| Condition | Classification |
|-----------|---------------|
| The field can be NULL on a reachable path (caller passes an empty/failed result, framework deserializes optional data) and the dereference runs → crash | **confirmed** |
| A caller or the framework guarantees the field is non-null by protocol (e.g. a message handler that only runs on a validated non-empty message) | **false-positive** (contract guarantees non-null) |
| The count field `obj->N` is guaranteed positive when the field is used, or the dereference is inside a loop that no-ops on count==0 and the field is only touched when count>0 | **false-positive** (empty state is handled) |
| The caller already validates `obj->P != NULL` before every call, and the function is only called from those sites | **false-positive** (validated at the call boundary) |
| The field is a fixed array / interior pointer that can never be NULL (`&x`, string literal, offsetof-style accessor) | **false-positive** (non-nullable by construction) |
| The deref sits INSIDE the same guard that tests the field (`if (obj->P != NULL) { use(obj->P); }`, the `else` of `if (obj->P == NULL)`, or the right side of `obj->P && ...`) | **false-positive** — the pipeline models these same-block guards and drops the site; if such a shape still reaches you, the reported `use_line`/`self-guard@N` says it is a different scope (the guard does not cover it) |
| The evidence is name-based only (fields merely share a `data`/`num` prefix with no usage coupling), or the source is unreadable | **dismissed** (insufficient evidence) |

### Common False Positives
- Framework/message handlers where the runtime guarantees the field is non-null
  for the message type being handled (IPC/callback contract).
- A counted loop `for (i = 0; i < obj->n; i++) use(obj->p[i])` where `obj->n == 0`
  is a legal empty result and the loop simply does not run.
- The caller constructs the object and fills the field before calling, so the
  field is non-null at every call site.
- The field is never actually NULL in practice — the null-check on another path
  is defensive, not evidence of a reachable NULL.

### Fix Suggestions
- Validate the field before the dereference, mirroring the codebase's own
  convention for that field: `if (obj->P == NULL) { <log/return>; }`.
- If an empty result is legal, handle it explicitly (early return / skip) rather
  than dereferencing; do not invent a return code — match the function's existing
  error/empty conventions.

### Examples

```c
// CONFIRMED — obj->p is null-checked elsewhere, but this deref is unguarded
void g(obj_t *obj) { if (obj->p == NULL) log("null"); use(obj->p); }

// DISMISSED — the deref sits inside the guard that tests it
void g(obj_t *obj) { if (obj->p != NULL) { use(obj->p); } }
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary
(confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Field dereference on an attacker/externally-influenced empty path (untrusted message, deserialized buffer) → reachable crash | HIGH |
| Field dereference on an internal/rare empty path (edge case, low exposure) | MEDIUM |
| Non-reachable defensive path, or evidence too weak to settle | LOW (dismissed) |
