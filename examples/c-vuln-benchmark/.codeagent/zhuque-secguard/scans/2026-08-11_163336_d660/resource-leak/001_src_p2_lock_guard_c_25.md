# Resource Leak in increment_counter

**CWE:** CWE-404

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p2_lock_guard.c:25`
- **Function:** `increment_counter`
- **Variable:** `g_mutex`

## Evidence

- **resource_acquire:** resource acquired in function increment_counter at line 25
- **call_path:** function increment_counter is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Ensure the resource acquired in `increment_counter` is released on **all** code paths,
including error and early-return paths:

```c
FILE *f = fopen(path, "r");
if (!f) return -1;
// ... use f ...
fclose(f);
return 0;
```

For handles with create/destroy or acquire/release semantics, pair every
acquire with a matching release. Use `goto cleanup` for multi-resource
functions.
