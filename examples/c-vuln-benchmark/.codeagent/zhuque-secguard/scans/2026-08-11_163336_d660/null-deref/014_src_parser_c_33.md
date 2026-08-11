# Null Deref in format_task_desc

**CWE:** CWE-476

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/parser.c:33`
- **Function:** `format_task_desc`
- **Variable:** `task`

## Evidence

- **nullable_source:** variable task has NULL_VALUE source
- **call_path:** function format_task_desc is reachable from entry
- **data_flow:** NULL value propagates to dereference at line 33
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Add a NULL check before dereferencing `task` in `format_task_desc`:

```c
if (task == NULL) {
    // handle error: return, log, or assert
    return -1;
}
// safe to use task here
```

Also ensure `task` is properly initialized on all code paths leading to this point.
