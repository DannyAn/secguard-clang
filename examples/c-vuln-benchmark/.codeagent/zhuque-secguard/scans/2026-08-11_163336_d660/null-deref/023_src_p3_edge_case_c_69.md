# Null Deref in FileCache_create

**CWE:** CWE-476

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p3_edge_case.c:69`
- **Function:** `FileCache_create`
- **Variable:** `fc`

## Evidence

- **nullable_source:** variable fc has NULL_VALUE source
- **call_path:** function FileCache_create is reachable from entry
- **data_flow:** NULL value propagates to dereference at line 69

## Classification

- **Suspicion Level:** confirmed
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Add a NULL check before dereferencing `fc` in `FileCache_create`:

```c
if (fc == NULL) {
    // handle error: return, log, or assert
    return -1;
}
// safe to use fc here
```

Also ensure `fc` is properly initialized on all code paths leading to this point.
