# Resource Leak in process_file

**CWE:** CWE-404

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p3_edge_case.c:83`
- **Function:** `process_file`
- **Variable:** `fc`

## Evidence

- **resource_acquire:** resource acquired in function process_file at line 83
- **call_path:** function process_file is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Ensure the resource acquired in `process_file` is released on **all** code paths,
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
