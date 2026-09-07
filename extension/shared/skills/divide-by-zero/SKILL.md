---
name: divide-by-zero
description: Classify divide-by-zero / modulo-by-zero evidence — a divisor that is not a provably non-zero constant. Maps to CWE-369.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-369
  severity: HIGH
---

## Divide By Zero Analysis (CWE-369)

### Evidence Pattern
A divide-by-zero candidate has:
- **divide_by_zero**: A `/` or `%` binary expression whose right operand is a variable, call result, or compound expression (not a non-zero literal, not `sizeof`)
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Find all `binary_expression` nodes with `/` or `%` operator
2. Take the right operand as the divisor
3. Skip a non-zero numeric literal or any `sizeof(...)` (compile-time constant)
4. Emit `DIVIDE_BY_ZERO` otherwise

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `x / (a - b)` where `a == b` is reachable | **confirmed** |
| `x / n` with `n` from external input | **suspected** |
| `x / 2`, `x / sizeof(T)` | **false-positive** (constant, safe) |

> **Pipeline pre-confirms, so these never reach this classification step:**
> - `x / obj->field` or `x % obj.field` (a struct/object field chain) — a
>   config/capacity value whose zero-invariant is established at object
>   initialization, not at the use site. The range filter upgrades these to
>   `confirmed` (auto-confirm) — a defensive-check gap to fix, not an AI question.
> - `x / g_name` (a module-global divisor) — same reasoning, also auto-confirmed.
> - `x / d` where the interval analysis proves `d == 0` (`d = 0; x / d`) — a
>   certain divide-by-zero, auto-confirmed.

### Common False Positives
- `x / 100` — constant divisor (safe)
- `x % sizeof(int)` — compile-time constant (safe)
- A divisor that is checked `if (n == 0) return;` immediately before (needs flow verification)
- A divisor reassigned to a provably non-zero constant before the division (`d = 0; d = 1; x / d`) — the convergence range flow proves it non-zero and suppresses it
