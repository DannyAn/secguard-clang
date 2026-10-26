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

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `divisor@<shape>` | the divisor's syntactic shape (`bare`/`field`/`global`/`call`/`compound`) | **read the ±8-line Code Context before confirming, for EVERY shape.** The shape says where the value comes from, NOT whether it is guarded: the pipeline already dropped every divisor it could prove non-zero (constant symbol, interval, same-function guard), so a row that reached you means no modelled guard exists — and the unmodelled ones are exactly what the window shows (`if (n == 0) return;`, `if (n == 0 \|\| idx >= count) return;`, `if (!n) goto out;`, `if (n == 0) n = DEFAULT;`). Confirming from the `Source` column alone is how guarded divisions were filed as real defects |
| `range@[lo,hi]` | the range engine's proved interval for the divisor — it contains 0 (else the filter would have dropped the row) | judge whether the 0 endpoint is actually reachable |
| `callers@<summary>` | the direct call-site census for a parameter divisor | check the callers passing non-constants for a 0 argument |

The verdict basis is the shape + `range@` + the Code Context window: a zero
guard in the window (any spelling, including a disjunctive
`if (x == 0 || y == 0) return;`) makes the division safe → **dismissed**; a
caller-counted non-constant flow toward 0 with no guard → **confirmed**.

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
> - `x / d` where the interval analysis proves `d == 0` (`d = 0; x / d`) — a
>   certain divide-by-zero, auto-confirmed.
> - `x / <non-zero constant symbol>` — folded like a literal.
>
> **`divisor@field` / `divisor@global` rows DO reach you as `suspected`:** a
> struct/object field or a module global is only "non-zero by construction" if
> something establishes it (init, config validation, a guard) — the pipeline
> does not assume it, and you must not either. Judge the Code Context window.

### Common False Positives
- `x / 100` — constant divisor (safe)
- `x % sizeof(int)` — compile-time constant (safe)
- A divisor that is checked before the division — `if (n == 0) return;`, `if (!n) goto out;`, `if (n == 0 || i >= count) return INVALID;`, `if (n == 0) n = DEFAULT;` — the guard is in the ±8-line window; when the pipeline does not model it (disjunctive forms, helper predicates), the row still reaches you as `suspected` and the window settles it
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
