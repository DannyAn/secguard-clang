---
name: deadlock
description: Classify deadlock evidence — lock-order inversion and nested locking patterns. Maps to CWE-667.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-667
  severity: HIGH
  domain: concurrency
---

## Deadlock Analysis (CWE-667)

### Evidence Pattern
A deadlock candidate has:
- **DEADLOCK event**: Lock-order inversion detected via lock graph cycle
- Two or more threads acquire locks in different orders
- Thread 1: `lock(A) → lock(B)`, Thread 2: `lock(B) → lock(A)` → cycle in lock graph

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

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Lock-order inversion detected (cycle in lock graph) | **confirmed** |
| All lock acquisitions follow consistent global order | **false-positive** |
| `timedlock` with timeout on all nested locks | **suspected** (recovery possible but complex) |
| Single lock, no nesting | **false-positive** |
| Lock-free implementation (atomics only) | **false-positive** |
| Same lock acquired twice (non-recursive mutex) | **confirmed** |

### Fix Suggestions
- Establish a global lock hierarchy and document it; always acquire in order
- Use `pthread_mutex_timedlock()` to detect and recover from deadlocks
- Consider a single coarse-grained lock if ordering is hard to maintain
- Refactor to avoid nested locking (split critical sections)
- Use lock-free data structures where possible (atomics, RCU)
- Run with ThreadSanitizer (TSan) to detect lock-order issues at runtime
- Use lock-ordering linters or static analysis to enforce the hierarchy