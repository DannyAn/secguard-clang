# Uninit in parse_args

**CWE:** CWE-457

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/parser.c:64`
- **Function:** `parse_args`
- **Variable:** `task`

## Evidence

- **uninit_use:** uninitialized variable used in function parse_args at line 64
- **call_path:** function parse_args is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Initialize `task` at declaration or ensure it is assigned before first use
in `parse_args`:

```c
// Option 1: initialize at declaration
int task = 0;

// Option 2: explicit initialization before use
task = compute_value();
if (error) return -1;
// now safe to use task
```

For struct members, use `memset(&task, 0, sizeof(task))` or designated
initializers to zero-fill before use.
