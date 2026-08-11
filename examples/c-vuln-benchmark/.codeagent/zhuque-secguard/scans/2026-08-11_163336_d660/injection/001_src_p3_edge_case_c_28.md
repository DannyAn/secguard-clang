# Injection in run_admin_command

**CWE:** CWE-78

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/p3_edge_case.c:28`
- **Function:** `run_admin_command`
- **Variable:** `system(cmd)`

## Evidence

- **unsafe_call:** unsafe function call in run_admin_command at line 28
- **call_path:** function run_admin_command is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Avoid passing user-controlled input to command execution functions in `run_admin_command`.

```c
// BAD:  system(user_input);
// GOOD: use execve() with explicit argument array
char *argv[] = {"/bin/ls", user_input, NULL};
execve("/bin/ls", argv, NULL);
```

If shell invocation is unavoidable, strictly validate/whitelist the input
and escape shell metacharacters before use.
