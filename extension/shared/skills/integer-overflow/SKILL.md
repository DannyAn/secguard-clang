---
name: integer-overflow
description: Classify integer overflow evidence — ARITH_OVERFLOW events from size calculations feeding malloc/memcpy. Maps to CWE-190.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-190
  severity: HIGH
  domain: boundary
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
| `size_mul_const_overflow` | `malloc(n * K)`, n is a function parameter | suspected |
| `size_add_overflow` | `malloc(n + 1)` / `malloc(n + m)`, n caller-influenced | possible |
| `size_sub_overflow` | `malloc(n - 1)`, n caller-influenced | possible |
| `integer_overflow` | wraparound inside a bounds check | possible |

### Dangerous Patterns

| Pattern | Risk | Why |
|---------|------|-----|
| `malloc(count * elem_size)` | Overflow → small alloc | `count * elem_size` wraps to small value |
| `calloc(count, size)` | Overflow → small alloc | implicit `count * size` wraps |
| `malloc(a + b)` | Overflow → small alloc | `a + b` wraps around |
| `malloc(n + 1)` with caller-controlled n | Overflow → small alloc | `n == SIZE_MAX` wraps to 0 |
| `memcpy(dst, src, a + b)` | Overflow → short copy | Copy size wraps, buffer overread |
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
| `a + b` where `a`, `b` are bounded constants | **false-positive** |
| Arithmetic on `int` (signed) feeding malloc | **suspected** (sign issues) |
| `size_add_overflow` / `size_sub_overflow` where the parameter is validated by every caller (e.g. clamped, or provably `< SIZE_MAX - offset`) | **false-positive** |
| `size_add_overflow` / `size_sub_overflow` where the parameter is raw user input (argv/getenv/recv length) with no clamp | **confirmed** |
| `size_mul_const_overflow` where the parameter is raw user input and `K >= 2` | **confirmed** |
| `size_mul_const_overflow` where the parameter is provably bounded to `< SIZE_MAX / K` by a guard | **false-positive** |

**Reasoning for the `possible` tier** (`size_add_overflow` / `size_sub_overflow`): the
pipeline cannot prove the parameter reaches an extreme value, so it delegates the
reachability question to you. Trace the parameter to its source — if it is derived
from user input (argv, getenv, recv, a network length field) with no clamp, the
overflow is realistic and should be **confirmed**; if it is a bounded length
(e.g. `strlen` of a fixed buffer, a loop counter, a validated length), it is
**false-positive**.

### Fix Suggestions
- Use `size_t` for all size calculations (never `int`)
- Check before multiply: `if (count > SIZE_MAX / elem_size) return NULL;`
- Check before add: `if (a > SIZE_MAX - b) return NULL;`
- Use compiler builtins: `__builtin_mul_overflow(count, elem_size, &total)`
- Use checked-allocation wrappers that validate internally
- Clamp `count` to a reasonable maximum before arithmetic