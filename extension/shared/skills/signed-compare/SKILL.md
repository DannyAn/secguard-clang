---
name: signed-compare
description: Classify signed-compare evidence — an unsigned variable compared with zero/negative, which is always false. Maps to CWE-681/CWE-195.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-681
  severity: MEDIUM
---

## Signed/Unsigned Comparison Analysis (CWE-681 / CWE-195)

### Evidence Pattern
A signed-compare candidate has:
- **signed_compare**: A `<`/`<=`/`>`/`>=` comparison where one operand is an `unsigned` variable and the other is `0` or a negative literal (e.g. `x < 0`, `x <= -1`, `0 > x`)
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Collect variable names declared with an `unsigned` type (`unsigned`, `size_t`, `uint*_t`, `uintptr_t`, ...) — including typedefs that resolve to unsigned (`typedef unsigned int my_uint; my_uint m`), resolved cross-file so a header typedef counts
2. Find relational `binary_expression` nodes
3. Flag when an unsigned variable is compared against `0`/negative in a way that is always false/true
4. Emit `SIGNED_COMPARE` otherwise (only when the declared type is provably unsigned, so the category is confirmed)

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `size_t i = n; while (i >= 0) i--;` — never terminates | **confirmed** |
| `unsigned len; if (len < 0) ...` — dead guard, bounds check silently passes | **confirmed** |
| `if (x < 0)` where `x` is genuinely `int` | **false-positive** (not unsigned) |
| A deliberate defensive `if (n > SOME_MAX)` with correct signedness | **false-positive** |

### Common False Positives
- Variables mis-detected as `unsigned` (e.g. a macro type position)
- Comparisons that are intentional dead-code sentinels
