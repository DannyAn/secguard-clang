# Buffer Overflow in validate_user_input

**CWE:** CWE-787

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/parser.c:77`
- **Function:** `validate_user_input`
- **Variable:** `strcpy(buf, user_input)`

## Evidence

- **buffer_access:** buffer access in function validate_user_input at line 77
- **call_path:** function validate_user_input is reachable from entry

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Validate the buffer size before accessing `strcpy(buf, user_input)` in `validate_user_input`:

```c
// Check bounds before write/read
if (offset + access_size > buffer_capacity) {
    return -1;  // or clamp the size
}
```

Prefer safe alternatives: `memcpy_s`, `strncpy_s`, `snprintf` instead of
`memcpy`, `strcpy`, `sprintf`. If using loop-based access, add an explicit
upper-bound check on the loop index.
