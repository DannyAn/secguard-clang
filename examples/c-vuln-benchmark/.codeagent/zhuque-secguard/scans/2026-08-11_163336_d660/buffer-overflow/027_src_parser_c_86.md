# Buffer Overflow in oob_read_example

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/parser.c:86`
- **Function:** `oob_read_example`
- **Variable:** `arr[i]`

## Evidence

- **buffer_access:** buffer access in function oob_read_example at line 86
- **call_path:** function oob_read_example is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `arr[i]` in `oob_read_example`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
