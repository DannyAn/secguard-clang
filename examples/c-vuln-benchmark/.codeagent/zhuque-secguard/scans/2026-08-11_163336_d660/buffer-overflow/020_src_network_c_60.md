# Buffer Overflow in parse_packet

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/network.c:60`
- **Function:** `parse_packet`
- **Variable:** `packet_queue[queue_size++]`

## Evidence

- **buffer_access:** buffer access in function parse_packet at line 60
- **call_path:** function parse_packet is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `packet_queue[queue_size++]` in `parse_packet`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
