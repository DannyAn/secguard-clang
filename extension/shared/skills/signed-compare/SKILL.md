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
- **signed_compare**: An ordering comparison between an `unsigned` variable and `0`/a negative literal whose result is a **tautology** because an unsigned value is never negative:
  - `u < 0`, `u <= -1`, `0 > u` → always false
  - `u >= 0`, `u > -1`, `0 <= u` → always true
- **call_path**: The function is reachable from an entry point

Note `u > 0` (`u != 0`) and `u <= 0` (`u == 0`) are **legitimate** checks and are not emitted.

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
| `unsigned ref_cnt; if (ref_cnt > 0)` — a non-zero check, not dead logic | **false-positive** |
| `unsigned x; if (x <= 0)` — a zero check, not dead logic | **false-positive** |
| A deliberate defensive `if (n > SOME_MAX)` with correct signedness | **false-positive** |

### Common False Positives
- Variables mis-detected as `unsigned` (e.g. a macro type position)
- Comparisons that are intentional dead-code sentinels
