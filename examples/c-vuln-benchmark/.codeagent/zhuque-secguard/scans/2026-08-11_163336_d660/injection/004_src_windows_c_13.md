# Injection in run_user_command

**CWE:** CWE-78

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/windows.c:13`
- **Function:** `run_user_command`
- **Variable:** `CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)`

## Evidence

- **unsafe_call:** unsafe function call in run_user_command at line 13
- **call_path:** function run_user_command is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Avoid passing user-controlled input to command execution functions in `run_user_command`.

```c
// BAD:  system(user_input);
// GOOD: use execve() with explicit argument array
char *argv[] = {"/bin/ls", user_input, NULL};
execve("/bin/ls", argv, NULL);
```

If shell invocation is unavoidable, strictly validate/whitelist the input
and escape shell metacharacters before use.
