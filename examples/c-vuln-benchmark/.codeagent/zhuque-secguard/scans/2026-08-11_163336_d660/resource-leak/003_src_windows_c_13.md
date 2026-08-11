# Resource Leak in run_user_command

**CWE:** CWE-404

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/windows.c:13`
- **Function:** `run_user_command`
- **Variable:** `si`

## Evidence

- **resource_acquire:** resource acquired in function run_user_command at line 13
- **call_path:** function run_user_command is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Ensure the resource acquired in `run_user_command` is released on **all** code paths,
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
