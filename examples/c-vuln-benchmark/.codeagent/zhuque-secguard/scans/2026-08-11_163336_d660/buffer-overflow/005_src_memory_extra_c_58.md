# Buffer Overflow in allocate_and_forget

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/memory_extra.c:58`
- **Function:** `allocate_and_forget`
- **Variable:** `strcpy(buf, "temporary")`

## Evidence

- **buffer_access:** buffer access in function allocate_and_forget at line 58
- **call_path:** function allocate_and_forget is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `strcpy(buf, "temporary")` in `allocate_and_forget`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
