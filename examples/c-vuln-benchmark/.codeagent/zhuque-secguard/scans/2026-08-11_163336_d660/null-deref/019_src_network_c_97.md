# Null Deref in main

**CWE:** CWE-476

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/network.c:97`
- **Function:** `main`
- **Variable:** `hdr`

## Evidence

- **nullable_source:** variable hdr has NULL_VALUE source
- **call_path:** function main is reachable from entry
- **data_flow:** NULL value propagates to dereference at line 97

## Classification

- **Suspicion Level:** confirmed
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Add a NULL check before dereferencing `hdr` in `main`:

```c
if (hdr == NULL) {
    // handle error: return, log, or assert
    return -1;
}
// safe to use hdr here
```

Also ensure `hdr` is properly initialized on all code paths leading to this point.
