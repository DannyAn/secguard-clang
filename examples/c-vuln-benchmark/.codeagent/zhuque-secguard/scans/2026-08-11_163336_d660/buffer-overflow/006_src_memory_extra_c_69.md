# Buffer Overflow in mismatched_free_example

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/memory_extra.c:69`
- **Function:** `mismatched_free_example`
- **Variable:** `strcpy(buf, "test")`

## Evidence

- **buffer_access:** buffer access in function mismatched_free_example at line 69
- **call_path:** function mismatched_free_example is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `strcpy(buf, "test")` in `mismatched_free_example`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
