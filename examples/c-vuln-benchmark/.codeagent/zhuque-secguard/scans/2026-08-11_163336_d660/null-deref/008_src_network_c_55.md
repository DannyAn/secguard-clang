# Null Deref in parse_packet

**CWE:** CWE-476

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/network.c:55`
- **Function:** `parse_packet`
- **Variable:** `header`

## Evidence

- **nullable_source:** variable header has NULL_VALUE source
- **call_path:** function parse_packet is reachable from entry
- **data_flow:** NULL value propagates to dereference at line 55
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Add a NULL check before dereferencing `header` in `parse_packet`:

```c
if (header == NULL) {
    // handle error: return, log, or assert
    return -1;
}
// safe to use header here
```

Also ensure `header` is properly initialized on all code paths leading to this point.
