# Buffer Overflow in process_buffer

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p2_raii_memory.c:46`
- **Function:** `process_buffer`
- **Variable:** `memcpy(handle->data, input, len)`

## Evidence

- **buffer_access:** buffer access in function process_buffer at line 46
- **call_path:** function process_buffer is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `memcpy(handle->data, input, len)` in `process_buffer`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
