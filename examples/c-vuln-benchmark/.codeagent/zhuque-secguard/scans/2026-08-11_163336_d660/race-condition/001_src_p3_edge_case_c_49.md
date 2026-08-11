# Race Condition in check_and_transfer

**CWE:** CWE-362

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p3_edge_case.c:49`
- **Function:** `check_and_transfer`

## Evidence

- **toctou:** time-of-check-time-of-use in check_and_transfer at line 49
- **call_path:** function check_and_transfer is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Eliminate the time-of-check-to-time-of-use (TOCTOU) race in `check_and_transfer` by
performing check and use atomically:

```c
// BAD: if (access(path, R_OK) == 0) { f = fopen(path, "r"); }
// GOOD: open the file directly and check the fd
int fd = open(path, O_RDONLY);
if (fd < 0) { /* handle */ }
FILE *f = fdopen(fd, "r");
```

For shared state, protect check-then-act sequences with a mutex:
lock before the check and hold the lock through the mutation. Avoid
`access()` + `fopen()` patterns; use `fopen()` and check the result.
