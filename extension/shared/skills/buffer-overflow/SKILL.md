---
name: buffer-overflow
description: Classify buffer overflow evidence — BUFFER_ACCESS events from unsafe memcpy/strcpy/sprintf/strcat calls, array/heap out-of-bounds writes, and format overflow. Maps to CWE-787.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-787
  severity: HIGH
---

## Buffer Overflow Analysis (CWE-787)

### Evidence Pattern
A buffer-overflow candidate has:
- **BUFFER_ACCESS event**: An unsafe function call (memcpy, strcpy, sprintf, strcat, gets)
- **No bounds check**: No guard checking buffer capacity before the unsafe call
- **Reachable**: The function is reachable from an entry point

Detector categories that route to this type:
- `buffer_overflow` — unsafe copy API call (memcpy/strcpy/strcat/gets/...)
- `array_oob_write` — constant index, a constant-valued variable index (`int n = 12; buf[n]`), or a loop bound past a fixed-size array, as a write
- `heap_oob_write` — loop bound provably exceeds a `malloc`/`calloc` size (e.g. `malloc(user_len)` + `i < user_len + 10`)
- `format_overflow` — `sprintf`/`wsprintf` into a known-capacity buffer with a non-constant source
- `bounded_copy_overflow` — **confirmed**: `strncpy(dst, src, n)` with a constant `n > sizeof(dst)` (provable overflow)
- `bounded_copy_var_size` — **possible**: `strncpy(dst, src, n)` where `dst` is a fixed array and `n` is a caller-influenced parameter (the length may exceed the capacity; reason over the call sites)
- `secure_copy_overflow` — **confirmed**: an Annex K `_s` function (`memcpy_s`/`strcpy_s`/`sprintf_s`/`strncpy_s`/`memset_s`/`asctime_s`/...) given a constant destination-capacity argument larger than the real buffer (`memcpy_s(dst, 100, src, 50)` with `char dst[8]`) — the lying size defeats the "secure" prefix
- `secure_copy_var_size` — **possible**: a `_s` function whose destination-capacity argument is a caller-influenced variable (may exceed the real buffer)
- `secure_constraint_violation` — **suspected**: the required size (copy count, or `strlen` of a literal source) exceeds the DECLARED capacity (`memcpy_s(dst, 16, src, 64)` / `strcpy_s(dst, 4, "hello")`). The runtime constraint handler fires — truncation or abort — no actual overflow but a real correctness bug; severity depends on the implementation's handler.
- `secure_scanf_overflow` — **confirmed**: a `scanf_s`/`sscanf_s`/`fscanf_s` `%s`/`%c`/`%[` conversion whose buffer-size argument (constant) exceeds the real buffer (`scanf_s("%s", buf, (rsize_t)100)` with `char buf[10]`)
- `secure_scanf_var_size` — **possible**: a `scanf_s` conversion whose buffer-size argument is a caller-influenced variable

Read-flavored events (`array_oob_read`, `heap_oob_read`) belong to the
`out-of-bounds` type (CWE-125), not this one.

### Safe Function Alternatives (P0 Exclusion)

| Unsafe | Safe Alternative | Notes |
|--------|-----------------|-------|
| `memcpy(dst, src, n)` | `memcpy_s(dst, sizeof(dst), src, n)` | Annex K |
| `strcpy(dst, src)` | `strcpy_s(dst, sizeof(dst), src)` | Annex K |
| `sprintf(buf, fmt, ...)` | `snprintf(buf, sizeof(buf), fmt, ...)` | Check return |
| `strcat(dst, src)` | `strcat_s(dst, sizeof(dst), src)` | Annex K |
| `gets(buf)` | `fgets(buf, sizeof(buf), stdin)` | Never use gets |

### Safe Wrappers (P1 Exemption)

| Wrapper | Guarantee | Why Safe |
|---------|-----------|----------|
| `SafeCopy_copy(dst, src, n)` | Checks `n > dst->capacity` | Bounds checked internally |
| `SafeCopy_strcpy(dst, src)` | Truncates to `capacity - 1` | Bounds checked internally |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Unsafe call + no bounds check + user-controlled size | **confirmed** |
| Unsafe call + bounds check before call (scope covers) | **false-positive** |
| Unsafe call inside safe wrapper | **false-positive** |
| `memcpy` with `sizeof(dst)` as size | **false-positive** |
| `strncpy` with `sizeof(dst) - 1` + null terminate | **false-positive** |
| Array write with constant index >= array size | **confirmed** |
| Loop bound provably exceeds array/heap allocation size (write) | **confirmed** |
| `sprintf(dst, ..., var)` into known-capacity `dst`, no size arg | **confirmed** |
| `sprintf` whose destination feeds `system`/`sqlite3_exec`/`CreateProcessA` | **false-positive** for buffer-overflow (injection is the root cause; SQL/command injection covers it) |
| Array access with variable index, no provable bound | **suspected** |
| `bounded_copy_overflow` (constant `n > sizeof(dst)`) | **confirmed** — the detector proved it |
| `bounded_copy_var_size` where `n` is a caller-influenced length (argv/getenv/recv length field, network packet length) with no clamp | **confirmed** |
| `bounded_copy_var_size` where `n` is validated by every caller to `<= sizeof(dst)` (clamp, guard, or a bounded `strlen` source) | **false-positive** |
| `bounded_copy_var_size` where `n` is a local counter / loop bound | **false-positive** (should not reach here — the detector only emits the parameter case) |
| `secure_copy_overflow` (constant size > capacity) | **confirmed** — the detector proved it |
| `secure_copy_var_size` where the capacity argument is attacker-controlled with no clamp | **confirmed** |
| `secure_copy_var_size` where the capacity argument is validated by every caller to `<= sizeof(dst)` | **false-positive** |
| `secure_constraint_violation` (required > declared capacity) | **confirmed** as a contract violation; report it as a correctness bug, noting the `_s` handler will truncate or abort rather than overflow |
| `secure_scanf_overflow` (constant buffer-size arg > capacity) | **confirmed** — the detector proved it |
| `secure_scanf_var_size` where the buffer-size arg is attacker-controlled with no clamp | **confirmed** |
| `secure_scanf_var_size` where the buffer-size arg is `sizeof(buf)` or a bounded length | **false-positive** |

**Reasoning for `bounded_copy_var_size`**: the pipeline cannot prove the variable
length exceeds the fixed destination, so it delegates reachability to you. Trace
`n` to its source — if it is attacker-controlled (argv, getenv, recv length, packet
header) with no clamp, the overflow is realistic and should be **confirmed**; if it
is a bounded length (strlen of a fixed buffer, a validated/capped length), it is
**false-positive**.

**Reasoning for `secure_copy_var_size`**: the same delegation applies to the `_s`
destination-capacity argument. The `_s` functions are only safe when the size
argument is truthful; a caller-controlled size that can exceed the real buffer is a
real overflow. Trace the size to its source and apply the same attacker-controlled
vs. bounded distinction.

### Fix Suggestions
- Replace with safe function: `memcpy_s(dst, sizeof(dst), src, n)`
- Add bounds check: `if (n > sizeof(dst)) return -1;`
- Use safe wrapper: `SafeCopy_copy(&buf, src, len)`
- For arrays: `if (index >= array_size) return -1;`
