# Buffer Overflow in process_user_data_unsafe

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p1_safecopy_wrapper.c:47`
- **Function:** `process_user_data_unsafe`
- **Variable:** `memcpy(buf, user_input, strlen(user_input))`

## Evidence

- **buffer_access:** buffer access in function process_user_data_unsafe at line 47
- **call_path:** function process_user_data_unsafe is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `memcpy(buf, user_input, strlen(user_input))` in `process_user_data_unsafe`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
