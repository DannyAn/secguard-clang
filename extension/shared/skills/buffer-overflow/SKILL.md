---
name: buffer-overflow
description: Classify buffer overflow evidence — BUFFER_ACCESS events from unsafe memcpy/strcpy/sprintf/strcat calls. Maps to CWE-120, CWE-787.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-120
  severity: HIGH
---

## Buffer Overflow Analysis (CWE-120, CWE-787)

### Evidence Pattern
A buffer-overflow candidate has:
- **BUFFER_ACCESS event**: An unsafe function call (memcpy, strcpy, sprintf, strcat, gets)
- **No bounds check**: No guard checking buffer capacity before the unsafe call
- **Reachable**: The function is reachable from an entry point

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
| Array access with variable index, no bounds check | **suspected** |

### Fix Suggestions
- Replace with safe function: `memcpy_s(dst, sizeof(dst), src, n)`
- Add bounds check: `if (n > sizeof(dst)) return -1;`
- Use safe wrapper: `SafeCopy_copy(&buf, src, len)`
- For arrays: `if (index >= array_size) return -1;`