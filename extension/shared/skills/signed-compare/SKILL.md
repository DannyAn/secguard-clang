---
name: signed-compare
description: Classify signed-compare evidence — an unsigned variable compared with zero/negative, which is always false. Maps to CWE-681/CWE-195.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-681
  severity: MEDIUM
  domain: security
---

## Signed/Unsigned Comparison Analysis (CWE-681 / CWE-195)

### Evidence Pattern
A signed-compare candidate has:
- **signed_compare**: An ordering comparison between an `unsigned` variable and `0`/a negative literal whose result is a tautology:
  - `u < 0`, `0 > u` → always **false** (an unsigned value is never negative)
  - `u >= 0`, `0 <= u` → always **true**
  - `u <= -1`, `u > -1` depend on the operand's **rank**: for `unsigned`/`size_t`/`uint32_t` (rank ≥ `int`) the `-1` converts to `UINT_MAX`/`SIZE_MAX`, so `u <= -1` is always **true** and `u > -1` is always **false**; only a narrow unsigned (`unsigned char`/`unsigned short`, promoted to `int`) matches the "never negative" reading (`u <= -1` false, `u > -1` true). Dead-guard vs dead-body is the wrong way round unless you get the rank right.
- **call_path**: The function is reachable from an entry point

Note `u > 0` (`u != 0`) and `u <= 0` (`u == 0`) are **legitimate** checks and are not emitted. A tautology is only a defect when the dead/always-taken branch gates a security-relevant bound (length, size, count); a harmless dead comparison is dismissed.

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `sign@<a>-vs-<b>` | the compared operand types the type-width model proved mismatched | apply the integer-promotion rule (rank vs `int`) to decide dead-guard vs dead-body before confirming |

### Detection Logic
1. Collect variable names declared with an `unsigned` type (`unsigned`, `size_t`, `uint*_t`, `uintptr_t`, ...) — including typedefs that resolve to unsigned (`typedef unsigned int my_uint; my_uint m`), resolved cross-file so a header typedef counts
2. Find relational `binary_expression` nodes
3. Flag when an unsigned variable is compared against `0`/negative in a way that is always false/true
4. Emit `SIGNED_COMPARE` otherwise (only when the declared type is provably unsigned, so the category is confirmed)

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
| `size_t i = n; while (i >= 0) i--;` — never terminates | **confirmed** |
| `unsigned len; if (len < 0) ...` — dead guard, bounds check silently passes | **confirmed** |
| `unsigned u; if (u <= -1)` — always-taken branch (rank ≥ `int`), e.g. a bounds check that never rejects | **confirmed** when the branch is security-relevant, else **false-positive** |
| `if (x < 0)` where `x` is genuinely `int` | **false-positive** (not unsigned) |
| `unsigned ref_cnt; if (ref_cnt > 0)` — a non-zero check, not dead logic | **false-positive** |
| `unsigned x; if (x <= 0)` — a zero check, not dead logic | **false-positive** |
| A deliberate defensive `if (n > SOME_MAX)` with correct signedness | **false-positive** |

### Common False Positives
- Variables mis-detected as `unsigned` (e.g. a macro type position)
- Comparisons that are intentional dead-code sentinels

### Examples

```c
// CONFIRMED — unsigned len < 0 is always false; the bounds guard silently passes
unsigned len; if (len < 0) return; use(len);

// DISMISSED — both operands are signed; the check is meaningful
int len; if (len < 0) return; use(len);
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Dead guard `if (len < 0)` on an unsigned length → bounds check silently bypassed → downstream overflow | HIGH |
| Never-terminating loop (`while (i >= 0) i--` on unsigned) | MEDIUM |
| Tautological comparison with no downstream safety impact | LOW |
