# Buffer Overflow in copy_message_unsafe

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p2_bounds_checked.c:37`
- **Function:** `copy_message_unsafe`
- **Variable:** `memcpy(dst, src, user_len)`

## Evidence

- **buffer_access:** buffer access in function copy_message_unsafe at line 37
- **call_path:** function copy_message_unsafe is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `memcpy(dst, src, user_len)` in `copy_message_unsafe`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
