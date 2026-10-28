---
name: format-string
description: Classify format string vulnerability evidence — printf-family called with non-literal format argument. Maps to CWE-134.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-134
  severity: HIGH
  domain: security
---

## Format String Vulnerability Analysis (CWE-134)

### Evidence Pattern
A format-string candidate has:
- **format_string**: A printf-family function is called where the format argument is not a string literal
- **api**: the format function called
- **format_arg**: the non-literal format argument expression
- **taint_source**: where the user-controlled value behind the format argument originates (when the taint filter proved one)
- **callsite_census** (when the format argument is a function parameter): the in-tree call-site argument census for that parameter — `all-literal` means every caller passes a compile-time constant
- **callsite_list** (when the argument is a function parameter): the concrete in-tree call sites (`literal`/`variable`/`tainted` @ file:line, bounded) — the non-constant callers to inspect, no grep needed
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `fmt-arg@<expr>` | the format argument expression | a non-literal (variable) format is the CWE-134 signal; a function **parameter** is attacker-reachable only when `callsites@` shows a non-constant argument or no in-tree call site — **pair with `callsites@` before confirming**; a constant string literal → **dismissed**; a local that is never externally controlled → judge |
| `callsites@<census>` | the in-tree call-site census for the format parameter | `N:all-literal` = every in-tree caller passes a compile-time constant → **dismissed**; `N:K-literal,J-var` = the var/tainted callers are where attacker input could enter → inspect those callers before confirming; token absent = no in-tree call site binds the parameter (an external TU may call it) |

### Functions Checked
`printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `vfprintf`, `vsprintf`, `vsnprintf`, `syslog`, `err`, `warn`, `errx`, `warnx`

### Detection Logic
1. Find all calls to printf-family functions
2. Extract the format argument (first argument for printf/sprintf, second for fprintf)
3. If the format argument is NOT a string literal (doesn't start with `"` or `L"`), emit FORMAT_STRING event
4. Skip calls that use `sizeof` in the expression (likely safe bounded writes)

### Evidence closure (read before any source read)

The candidate file already embeds the decisive cross-file facts the pipeline
resolved: an in-scan callee body under `## Callee Definition` (Hint
`callee@<file>:<line>`) and project macro bodies under `## Macro Definition`
(Hint `macro@<name>`). Read those sections first — they are in-file and cost no
lookup. Only a fact that is NOT embedded may be resolved with `secguard_def` /
`secguard def <symbol>` (batch related symbols); never grep the repository for a
definition, and never dismiss a macro/callee as "out of scan" before checking
the embedded section and the indexed lookup.

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| printf(user_input) — format is external input | **confirmed** |
| printf(log_msg) — format is a function parameter, `callsites@` shows a non-constant caller | **confirmed** (attacker-reachable via that caller) |
| printf(log_msg) — format is a function parameter, `callsites@N:all-literal` | **dismissed** (every in-tree caller passes a compile-time constant) |
| printf(log_msg) — format is a function parameter, no `callsites@` token | **judge** (no in-tree call site: an external TU may call it) |
| printf(local_buf) — format is a local, never externally controlled | **dismissed** |
| printf("%s", user_input) — format is literal | **false-positive** (safe) |
| snprintf(buf, sizeof(buf), fmt, ...) — bounded with sizeof | **false-positive** (safe) |

### Common False Positives
- `printf("%s\n", msg)` — format is a string literal (safe)
- `snprintf(buf, sizeof(buf), "%d", val)` — bounded write with literal format (safe)
- `printf(const_format_string)` — format is a compile-time constant (safe, but detector can't verify)
- A log/format wrapper whose every in-tree call site passes a string literal (`callsites@N:all-literal`) — the pipeline drops these before they reach you; if one slips through WITH the census token, **dismiss it from that token** (no source read, no `grep`). A vprintf-style wrapper (`vsnprintf(buf, n, fmt, args)` with `fmt` a parameter) is exactly this shape: the parameter being non-literal is NOT the defect when every caller binds it to a literal, and an object-like macro whose body is a string literal (`#define MSG_FMT "%d"`) counts as a literal caller

### Fix Suggestions
- Always use string literal as format: `printf("%s", user_input)` instead of `printf(user_input)`
- Use `fputs()` instead of `printf()` when no formatting is needed
- Use `snprintf()` with bounded buffer size to prevent overflow
- Never pass user-controlled data as the format argument

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| `printf`/`sprintf` with user-controlled format | CRITICAL (arbitrary read/write) |
| Non-literal format variable, source unknown | HIGH (dismissed) |
| `syslog`/`err`/`warn` with non-literal format | HIGH (stack data leak) |