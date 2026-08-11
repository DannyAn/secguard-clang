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

### Dangerous Patterns

| Pattern | Risk | Why |
|---------|------|-----|
| `malloc(count * elem_size)` | Overflow → small alloc | `count * elem_size` wraps to small value |
| `malloc(a + b)` | Overflow → small alloc | `a + b` wraps around |
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

### Fix Suggestions
- Use `size_t` for all size calculations (never `int`)
- Check before multiply: `if (count > SIZE_MAX / elem_size) return NULL;`
- Check before add: `if (a > SIZE_MAX - b) return NULL;`
- Use compiler builtins: `__builtin_mul_overflow(count, elem_size, &total)`
- Use checked-allocation wrappers that validate internally
- Clamp `count` to a reasonable maximum before arithmetic