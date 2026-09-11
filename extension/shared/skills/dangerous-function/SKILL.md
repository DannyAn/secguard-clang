---
name: dangerous-function
description: Classify dangerous-function evidence — a call to a banned/obsolete libc function. Maps to CWE-676.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-676
  severity: MEDIUM
---

## Dangerous Function Analysis (CWE-676)

### Evidence Pattern
A dangerous-function candidate has:
- **DANGEROUS_FUNCTION event** with category `dangerous_function`
- The event's `variable` is the banned function called (`gets`, `mktemp`, `gethostbyname`, `bcopy`, ...)
- **call_path**: The containing function is reachable from an entry point

### Detection Logic
1. Find every call to a function in the banned list
2. The list = a built-in dangerous/obsolete set, PLUS the project's
   `secguard.toml` `[banned_functions]` `names` (enterprise policy extension)
3. Emit `DANGEROUS_FUNCTION` for each call site

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| A call to `gets` / `mktemp` / `tmpnam` / `gethostbyname` / `gethostbyaddr` / `inet_addr` / `bcmp` / `bcopy` / `bzero` (or a config-banned name) | **confirmed** |
| A call to a function NOT in the banned list | **false-positive** (the detector never emits it) |

The list is a fixed policy: these functions are obsolete or inherently dangerous
regardless of surrounding code, so the pipeline auto-confirms them (a name match,
not a may-analysis). `strcpy`/`sprintf`/`system` are deliberately NOT in this list
— `buffer-overflow` and `injection` handle those context-sensitively.

### Common False Positives
- None by construction: the detection is an exact-name match on an uncontested
  obsolete/dangerous list. A codebase that deliberately vendors these functions
  (e.g. a compatibility `bzero`) is an intentional policy exception to review.

### Fix Suggestions
- `gets(buf)` → `fgets(buf, sizeof(buf), stdin)`
- `mktemp(t)` / `tmpnam(t)` → `mkstemp(t)` (or `mkstemps`)
- `gethostbyname(n)` / `gethostbyaddr(...)` → `getaddrinfo(...)`
- `inet_addr(s)` → `inet_pton(AF_INET, s, &addr)`
- `bcmp`/`bcopy`/`bzero` → `memcmp`/`memmove`/`memset`

### Severity Matrix
| Shape | Severity |
|-------|----------|
| Call to a banned/obsolete function | MEDIUM (policy violation) |
