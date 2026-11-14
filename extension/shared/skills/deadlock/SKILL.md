---
name: deadlock
description: Classify deadlock evidence — lock-order inversion and nested locking patterns. Maps to CWE-667.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-667
  severity: MEDIUM
  domain: concurrency
---

## Deadlock Analysis (CWE-667)

### Evidence Pattern
A deadlock candidate has:
- **DEADLOCK event**: Lock-order inversion detected via lock graph cycle
- Two or more threads acquire locks in different orders
- Thread 1: `lock(A) → lock(B)`, Thread 2: `lock(B) → lock(A)` → cycle in lock graph
- **deadlock**: the inversion site
- **lock_pair**: this function locks A then B
- **reverse_order**: the function that acquires the same locks in the opposite order

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `locks@A\|B` | this function acquires lock A then lock B (a LOCK_ORDER edge) | match the inversion pair across functions |
| `reverse@<fn>` | function `<fn>` acquires the same locks in the opposite order | the cycle is real — but confirm only when BOTH orders are reachable AND the two inversion sites can run concurrently |

### Dangerous Patterns

| Pattern | Risk | Why |
|---------|------|-----|
| `lock(A); lock(B);` in one function, `lock(B); lock(A);` in another | Deadlock | Lock-order inversion |
| `lock(A); lock(B);` + `lock(B); lock(C);` + `lock(C); lock(A);` | Deadlock | 3-lock cycle |
| `lock(A); ... lock(A);` (recursive without recursive mutex) | Deadlock | Self-deadlock |
| `lock(A); lock(B);` with no timeout | Deadlock | No recovery possible |

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| All threads acquire locks in the same global order | No cycle in lock graph |
| `pthread_mutex_timedlock()` with timeout | Can recover from deadlock |
| Single coarse-grained lock (no nesting) | No lock-order issue |
| Recursive mutex with documented re-entrancy | Self-deadlock safe |
| Lock-free data structures (atomics, RCU) | No locks, no deadlock |

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
| Lock-order inversion (cycle in lock graph) whose two orders are BOTH reachable and can run concurrently | **confirmed** |
| A cycle whose two inversion sites cannot run concurrently (a single-threaded init path, mutually exclusive branches) | **false-positive** |
| All lock acquisitions follow consistent global order | **false-positive** |
| A lock-order cycle that includes a `pthread_mutex_timedlock` acquisition | **confirmed** — ETIMEDOUT recovery does NOT remove the inversion; it only lowers severity. Do not dismiss on "timeout allows recovery" |
| Single lock, no nesting | **false-positive** |
| Lock-free implementation (atomics only) | **false-positive** |
| Same lock acquired twice (non-recursive mutex) | **confirmed** |

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Establish and document a global lock order and acquire
  every path in that order; where ordering is hard, collapse to a single
  coarse-grained lock, refactor to avoid nested locking, or use lock-free
  primitives (atomics/RCU).
- **Required conditions** — The full acquire set on each concurrent path must be
  known (the finding's two lock sites and any other locks they take) before the
  order is chosen; `pthread_mutex_timedlock` only detects/recovers, it does not
  remove the inversion.
- **Validation** — Confirm the two conflicting paths now acquire in one order,
  run ThreadSanitizer / a lock-order linter, and re-scan to confirm the cycle no
  longer reports.

### Examples

```c
// CONFIRMED — A then B in one path, B then A in another (both reachable & concurrent)
void f(void) { lock(A); lock(B); ... }
void g(void) { lock(B); lock(A); ... }

// DISMISSED — both paths acquire in the same order
void h(void) { lock(A); lock(B); ... }
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Lock-order inversion cycle (confirmed) | MEDIUM |
| Self-deadlock (non-recursive re-lock) | MEDIUM |
| Cycle that includes a `pthread_mutex_timedlock` acquisition | MEDIUM (dismissed — timeout allows recovery) |