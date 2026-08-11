# Format String in log_user_message

**CWE:** CWE-134

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/parser.c:45`
- **Function:** `log_user_message`
- **Variable:** `printf(user_msg)`

## Evidence

- **format_string:** printf-family called with non-literal format in log_user_message at line 45
- **call_path:** function log_user_message is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Use a constant format string in `log_user_message`; never let user input be the format
argument:

```c
// BAD:  printf(user_input);
// GOOD: printf("%s", user_input);
```

If dynamic formatting is needed, use `vsnprintf` with a fixed-size buffer
and a caller-specified format string that is validated against a whitelist.
