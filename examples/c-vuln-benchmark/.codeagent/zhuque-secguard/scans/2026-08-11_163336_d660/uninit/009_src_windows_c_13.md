# Uninit in run_user_command

**CWE:** CWE-457

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/windows.c:13`
- **Function:** `run_user_command`
- **Variable:** `pi`

## Evidence

- **uninit_use:** uninitialized variable used in function run_user_command at line 13
- **call_path:** function run_user_command is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Initialize `pi` at declaration or ensure it is assigned before first use
in `run_user_command`:

```c
// Option 1: initialize at declaration
int pi = 0;

// Option 2: explicit initialization before use
pi = compute_value();
if (error) return -1;
// now safe to use pi
```

For struct members, use `memset(&pi, 0, sizeof(pi))` or designated
initializers to zero-fill before use.
