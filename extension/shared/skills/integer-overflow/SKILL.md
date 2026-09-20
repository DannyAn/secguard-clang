---
name: integer-overflow
description: Classify integer overflow evidence — ARITH_OVERFLOW events from size calculations feeding malloc/memcpy. Maps to CWE-190.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-190
  severity: HIGH
  domain: semantic
---

## Integer Overflow Analysis (CWE-190)

### Evidence Pattern
An integer-overflow candidate has:
- **ARITH_OVERFLOW event**: An arithmetic operation (a + b, a * b) on size-typed values
- **Sink context**: The result flows into `malloc`, `calloc`, `realloc`, `memcpy`, `memset`
- **No overflow check**: No guard checking `a > SIZE_MAX - b` before the operation

The `category` field encodes the confidence tier the pipeline already computed:

| Category | Pattern | Static verdict |
|----------|---------|----------------|
| `size_calc_overflow` | `malloc(n * m)` / `malloc(n * sizeof(T))` / `calloc(n, m)` | suspected |
| `size_mul_const_overflow` | `malloc(n * K)`, n is a function parameter and `K >= 256` | suspected |
| `integer_overflow` | wraparound inside a bounds check | possible |

### Dangerous Patterns

| Pattern | Risk | Why |
|---------|------|-----|
| `malloc(count * elem_size)` | Overflow → small alloc | `count * elem_size` wraps to small value |
| `calloc(count, size)` | Overflow → small alloc | implicit `count * size` wraps |
| `char buf[n * m]` | Overflow → small stack array | VLA with wrapped size |

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `malloc(sizeof(dst))` | Constant size, no arithmetic |
| `malloc(count * sizeof(type))` with checked `count` | Count validated before multiply |
| `if (a > SIZE_MAX - b) return NULL; total = a + b;` | Explicit overflow check |
| `__builtin_add_overflow(a, b, &result)` | Compiler-checked overflow |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Arithmetic on sizes + flows to malloc + no overflow check | **confirmed** |
| Arithmetic on sizes + flows to malloc + checked bounds | **false-positive** |
| `count * elem_size` with user-controlled `count`, no check | **confirmed** |
| Constant expression (no variables) | **false-positive** |
| A size variable assigned a single small constant (`size_t n = 10; malloc(n * n)`) — the convergence range flow proves it bounded and suppresses it | **false-positive** |
| Arithmetic on `int` (signed) feeding malloc | **dismissed** (sign issues) |
| `size_mul_const_overflow` where the parameter is raw user input and `K >= 256` | **confirmed** |
| `size_mul_const_overflow` where the parameter is provably bounded to `< SIZE_MAX / K` by a guard | **false-positive** |

Note: `malloc(n + 1)` / `malloc(n - 1)` (null-terminator / off-by-one idioms) and
`malloc(n * K)` with a small `K < 256` (doubling, small magic numbers) are NOT
emitted — their overflow requires an operand within one bit of the type maximum,
which is implausible, so the detector no longer surfaces them.

### Fix Suggestions
- Use `size_t` for all size calculations (never `int`)
- Check before multiply: `if (count > SIZE_MAX / elem_size) return NULL;`
- Check before add: `if (a > SIZE_MAX - b) return NULL;`
- Use compiler builtins: `__builtin_mul_overflow(count, elem_size, &total)`
- Use checked-allocation wrappers that validate internally
- Clamp `count` to a reasonable maximum before arithmetic

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Overflow feeds an allocation/copy size with an attacker-controlled operand → undersized alloc → later heap overflow | CRITICAL |
| Overflow feeds malloc/memcpy size, bounded operand, no check | HIGH |
| `possible` tier (unsigned wraparound inside a bounds check, not proven reachable) | MEDIUM (possible) |
| Signed `int` arithmetic feeding malloc (sign-conversion risk) | MEDIUM (dismissed) |