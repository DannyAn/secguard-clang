# Buffer Overflow in alloc_entry

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/allocator.c:31`
- **Function:** `alloc_entry`
- **Variable:** `g_entries[g_entry_count++]`

## Evidence

- **buffer_access:** buffer access in function alloc_entry at line 31
- **call_path:** function alloc_entry is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `g_entries[g_entry_count++]` in `alloc_entry`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
