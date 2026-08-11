# Resource Leak in drop_and_elevate

**CWE:** CWE-404

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/windows.c:45`
- **Function:** `drop_and_elevate`
- **Variable:** `hToken`

## Evidence

- **resource_acquire:** resource acquired in function drop_and_elevate at line 45
- **call_path:** function drop_and_elevate is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Ensure the resource acquired in `drop_and_elevate` is released on **all** code paths,
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
