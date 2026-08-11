# Memory Leak in demo_unsafe_signal

**CWE:** CWE-401

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/concurrency.c:104`
- **Function:** `demo_unsafe_signal`
- **Variable:** `g_global_ptr`

## Evidence

- **memory_alloc:** allocation in function demo_unsafe_signal at line 104
- **call_path:** function demo_unsafe_signal is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Ensure `g_global_ptr` is freed on **all** code paths in `demo_unsafe_signal`, including error paths:

```c
char *g_global_ptr = malloc(size);
if (!g_global_ptr) return -1;
// ... use g_global_ptr ...
free(g_global_ptr);
g_global_ptr = NULL;
return 0;
```

For complex control flow, use a `goto cleanup` pattern or RAII-style
create/destroy wrapper functions to guarantee release.
