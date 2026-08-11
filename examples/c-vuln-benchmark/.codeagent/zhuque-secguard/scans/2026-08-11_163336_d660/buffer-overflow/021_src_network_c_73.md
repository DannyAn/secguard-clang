# Buffer Overflow in process_packets

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/network.c:73`
- **Function:** `process_packets`
- **Variable:** `packet_queue[i]`

## Evidence

- **buffer_access:** buffer access in function process_packets at line 73
- **call_path:** function process_packets is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `packet_queue[i]` in `process_packets`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
