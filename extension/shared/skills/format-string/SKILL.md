---
name: format-string
description: Classify format string vulnerability evidence — printf-family called with non-literal format argument. Maps to CWE-134.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-134
  severity: HIGH
---

## Format String Vulnerability Analysis (CWE-134)

### Evidence Pattern
A format-string candidate has:
- **format_string**: A printf-family function is called where the format argument is not a string literal
- **call_path**: The function is reachable from an entry point

### Functions Checked
`printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `vfprintf`, `vsprintf`, `vsnprintf`, `syslog`, `err`, `warn`, `errx`, `warnx`

### Detection Logic
1. Find all calls to printf-family functions
2. Extract the format argument (first argument for printf/sprintf, second for fprintf)
3. If the format argument is NOT a string literal (doesn't start with `"` or `L"`), emit FORMAT_STRING event
4. Skip calls that use `sizeof` in the expression (likely safe bounded writes)

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| printf(user_input) — format is external input | **confirmed** |
| printf(log_msg) — format is a variable | **suspected** (may be safe if controlled) |
| printf("%s", user_input) — format is literal | **false-positive** (safe) |
| snprintf(buf, sizeof(buf), fmt, ...) — bounded with sizeof | **false-positive** (safe) |

### Common False Positives
- `printf("%s\n", msg)` — format is a string literal (safe)
- `snprintf(buf, sizeof(buf), "%d", val)` — bounded write with literal format (safe)
- `printf(const_format_string)` — format is a compile-time constant (safe, but detector can't verify)

### Fix Suggestions
- Always use string literal as format: `printf("%s", user_input)` instead of `printf(user_input)`
- Use `fputs()` instead of `printf()` when no formatting is needed
- Use `snprintf()` with bounded buffer size to prevent overflow
- Never pass user-controlled data as the format argument

### Severity Matrix
| Pattern | Severity |
|---------|----------|
| printf(user_controlled) | CRITICAL (can read/write arbitrary memory) |
| printf(variable) | HIGH (may be exploitable depending on source) |
| syslog(priority, variable) | HIGH (can leak stack data) |