# Double Free in main

**CWE:** CWE-415

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/allocator.c:123`
- **Function:** `main`
- **Variable:** `e2`

## Evidence

- **double_free:** variable freed twice in function main at line 123
- **call_path:** function main is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Prevent double-free of `e2` in `main` by setting the pointer to NULL
after the first free:

```c
free(e2);
e2 = NULL;  // subsequent free(NULL) is a safe no-op
```

For complex ownership, track the allocation state explicitly with a flag
or use a wrapper that checks `if (ptr != NULL)` before freeing.
