---
name: divide-by-zero
description: Classify divide-by-zero / modulo-by-zero evidence — a divisor that is not a provably non-zero constant. Maps to CWE-369.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-369
  severity: HIGH
  domain: semantic
---

## Divide By Zero Analysis (CWE-369)

### Evidence Pattern
A divide-by-zero candidate has:
- **divide_by_zero**: A `/` or `%` binary expression whose right operand is a variable, call result, or compound expression (not a non-zero literal, not `sizeof`)
- **divisor_interval**: (when present) the range engine's own conclusion for the divisor — a tighter-than-top interval that still includes 0, e.g. `divisor d interval is [0, 1] (includes 0)`. Zero is reachable inside that interval; the classifier judges whether a reaching path is real
- **param_flow**: (when present) the call-site census for a parameter divisor the pipeline could not settle, e.g. `divisor d is a parameter: 2 direct call sites, 1 pass non-zero constants`. Judge the callers that pass a non-constant
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
| `x / n` where `n` is attacker-controlled (argv / getenv / recv length) and unguarded | **confirmed** (the attacker can make n == 0) |
| `x / n` where `n` is a bounded local, a loop counter, or a checked length | **false-positive** (n cannot be zero on any reachable path) |
| `x / n` where `n`'s origin cannot be settled from the context | **dismissed** |
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

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Divisor attacker-controlled (argv/getenv/recv) and unguarded → reachable crash | HIGH |
| Provable certain divide-by-zero (`d = 0; x / d`) | HIGH |
| Auto-confirmed struct-field / global divisor (defensive-check gap) | MEDIUM |
| Divisor origin unsettled | MEDIUM (dismissed) |
