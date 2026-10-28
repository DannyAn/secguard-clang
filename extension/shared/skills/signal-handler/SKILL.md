---
name: signal-handler
description: Classify signal handler evidence — a signal(2) handler that calls a non-async-signal-safe libc function. Maps to CWE-479.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-479
  severity: HIGH
  domain: security
---

## Signal Handler Analysis (CWE-479)

### Evidence Pattern
A signal-handler candidate has:
- **signal_handler_unsafe**: the non-async-signal-safe call (e.g. `malloc`, `printf`, `pthread_mutex_lock`) with category `signal_handler_unsafe`
- The event's `function` is the handler registered via `signal(SIGxxx, handler)`
- **call_path**: The registering function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `async-unsafe@<fn>` | the handler calls this function, which is off the POSIX async-signal-safe list | a certain CWE-479 — verify the call is inside the handler, then confirm |

`async-unsafe@` names the offending call; the defect is the
non-reentrancy itself, so no dataflow proof is needed beyond the call
being in the handler.

### Detection Logic
1. Find `signal(SIGxxx, handler)` registrations where `handler` is a named function (not `SIG_DFL`/`SIG_IGN`)
2. Find the handler's function definition
3. Emit `SIGNAL_HANDLER` for each DIRECT call to a known non-async-signal-safe libc function in its body

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
| A registered handler calls `malloc`/`free`/`printf`/`pthread_mutex_lock`/`syslog`/... | **confirmed** |
| The handler calls only async-signal-safe functions (`write`, `close`, `fork`, `_exit`, ...) | **false-positive** (the detector never emits it) |

The unsafe list is the POSIX async-signal-safe list inverted: a direct call to a
function absent from that list is a certain defect, so the pipeline auto-confirms
it. `read`/`write`/`open`/`close`/`socket`/`send`/`recv`/`connect`/`fcntl`/`fork`/
`exec*`/`_exit`/`abort` are async-signal-safe and are never reported.

### Common False Positives
- The detector only reports DIRECT calls in the handler body; it never flags a
  helper function the handler calls (transitive cases are out of scope), and it
  does not flag the async-signal-safe functions listed above.

### Fix Suggestions
- Do only async-signal-safe work in the handler: set a `volatile sig_atomic_t`
  flag and return; let the main loop do the heavy lifting
- If logging is required, use `write(fd, ...)` to a pre-opened fd, not `printf`/`syslog`
- Never allocate or take a lock in a signal handler

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Direct call to a non-async-signal-safe function in a registered handler | HIGH |
