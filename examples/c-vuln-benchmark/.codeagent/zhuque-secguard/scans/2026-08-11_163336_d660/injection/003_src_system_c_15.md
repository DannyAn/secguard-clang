# Injection in execute_user_command

**CWE:** CWE-78

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/system.c:15`
- **Function:** `execute_user_command`
- **Variable:** `system(cmd)`

## Evidence

- **unsafe_call:** unsafe function call in execute_user_command at line 15
- **call_path:** function execute_user_command is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Avoid passing user-controlled input to command execution functions in `execute_user_command`.

```c
// BAD:  system(user_input);
// GOOD: use execve() with explicit argument array
char *argv[] = {"/bin/ls", user_input, NULL};
execve("/bin/ls", argv, NULL);
```

If shell invocation is unavoidable, strictly validate/whitelist the input
and escape shell metacharacters before use.
