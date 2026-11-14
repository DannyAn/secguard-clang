---
name: stack-address-escape
description: Classify stack-address-escape evidence — a function returns or leaks the address of a non-static local. Maps to CWE-562.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-562
  severity: CRITICAL
  domain: security
---

## Stack Address Escape Analysis (CWE-562)

### Evidence Pattern
A stack-address-escape candidate has:
- **stack_escape**: the escape site (a `return`, a store, or a `pthread_create`
  argument) with category `return_stack_address` / `escape_via_store` /
  `escape_via_async_arg`
- **declaration**: the local's declaration-line:escape-line origin
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `object@<name>` | the non-static local whose address escapes | the dangling object; its declaration is in `origin` |
| `static@no` | storage class is auto (a static local is exempted at the detector, so it never reaches you) | confirms the frame dies at return |
| `escape-kind@return` | the address escapes by return | a certain dangling pointer — confirm |
| `escape-kind@store` | the address is stored into a non-local | judge whether the target outlives the frame |
| `escape-kind@async-arg` | the address is passed as `pthread_create`'s 4th argument | judge the thread's lifetime vs the frame |

`escape-kind@return` + `static@no` settles the row from the hint alone: returning
the address of an auto local is a certain CWE-562. The store / async-arg shapes
need the `## Code Context` (±8 lines) to judge the target's lifetime against the
frame's.

### Detection Logic
1. Collect each function's non-static locals (name + array shape + declaration line)
2. For each `return`, resolve the returned expression: an address-of local
   (`&local`, `&local.f`, `&arr[2]`) or a bare local array decay (`return arr`)
3. For each assignment, resolve a store of an address-of-local / array decay into
   a non-local (global / heap pointee / non-local array element)
4. For each `pthread_create`, resolve the 4th argument as an async body argument
5. Emit `STACK_ESCAPE` with the escape channel category; `return_stack_address`
   is auto-confirmed, the other two stay suspected

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
| `escape-kind@return` + `static@no` (address of an auto local returned) | **confirmed** |
| `escape-kind@async-arg` and the registered body is readable and does not copy the argument before the frame dies | **confirmed** |
| `escape-kind@store` into a non-local (global / `static` / heap pointee) | **confirmed** — the address of an auto local outlives the frame it points into, so a later read through that non-local is a dangling pointer. Only `*p = local` (copying the VALUE, not the address) or a store the pipeline proves is never read after the frame dies is safe |
| `escape-kind@async-arg` where the thread is `join`ed before the frame dies (synchronous use) | **dismissed** |
| returning the address of a global / parameter, or a string literal | **false-positive** (the detector never emits it) |

The return shape is AST-deterministic, so the pipeline already confirmed it; your
role is to verify the statement matches (a multi-line macro-wrapped return may
need the `## Macro Definition`). The store/async shapes are suspected: the
pipeline proved the address reaches a live location, not that the location
outlives the frame.

### Common False Positives
- `static` local — the pipeline already exempts it (its storage outlives the
  frame); do not over-turn a `static@no` into a dismiss
- returning the address of a global / a parameter / a string literal
- `pthread_create`'s argument that is copied into the thread's own storage
  before the frame dies, or a thread that is `join`ed synchronously

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Return the value through an out-parameter
  (`int f(int *out)`) instead of the address of a local; `static`-qualify the
  object when a single shared instance is intended; or heap-allocate and document
  the ownership transfer.
- **Required conditions** — Pick the storage by the object's lifetime: `static`
  makes one shared instance (not reentrant), heap transfer needs the caller to
  free it; confirm the intended lifetime before choosing.
- **Validation** — Confirm no path reads the escaped address after the frame
  returns, the chosen storage outlives every use, and the re-scan no longer
  reports the location.

### Examples

```c
// CONFIRMED — the address of an auto local escapes the frame
int *f(void) { int x; return &x; }

// DISMISSED — a static local's storage outlives the frame
int *f(void) { static int x; return &x; }
```

### Severity Matrix

`status` (confirmed / dismissed) and `severity`
(low / medium / high / critical) are **two independent axes** — never collapse
them into one column. `status` is the *evidence verdict* ("is it real?"),
`severity` is the *impact* ("how bad if real?"). The front-matter
`metadata.severity` is the type's **default** for a typical confirmed finding,
not a ceiling: pick each finding's severity from the table below.

| Severity | Meaning |
|----------|---------|
| CRITICAL | Attacker-reachable code execution / memory corruption, full data or credential compromise, or a live hardcoded secret |
| HIGH     | A certain or realistically-reachable memory-corruption / crash / DoS / auth-bypass / secret-disclosure defect |
| MEDIUM   | A real defect with limited impact (bounded resource leak, non-sensitive info disclosure, edge-case-only trigger) |
| LOW      | Defense-in-depth only, harmless dead code, or a weak-evidence issue that is dismissed |

**Verdicts**: `confirmed` (proved defect) or `dismissed` (everything else —
false positive OR a candidate you could not settle after reading its source).
`dismissed` → `low`.

| Shape | Reachability / exposure | Severity |
|-------|------------------------|----------|
| `escape-kind@return` (dangling pointer dereferenced by the caller) | return reaches a caller-controlled path | CRITICAL |
| `escape-kind@store` / `escape-kind@async-arg` | address reaches a live location but the deref is not proven | HIGH |
