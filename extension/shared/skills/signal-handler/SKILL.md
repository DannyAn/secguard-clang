---
name: signal-handler
description: Classify signal handler evidence — a signal(2) handler that calls a non-async-signal-safe libc function. Maps to CWE-479.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-479
  severity: HIGH
---

## Signal Handler Analysis (CWE-479)

### Evidence Pattern
A signal-handler candidate has:
- **SIGNAL_HANDLER event** with category `signal_handler_unsafe`
- The event's `variable` is the non-async-signal-safe function called (e.g. `malloc`, `printf`, `pthread_mutex_lock`)
- The event's `function` is the handler registered via `signal(SIGxxx, handler)`
- **call_path**: The registering function is reachable from an entry point

### Detection Logic
1. Find `signal(SIGxxx, handler)` registrations where `handler` is a named function (not `SIG_DFL`/`SIG_IGN`)
2. Find the handler's function definition
3. Emit `SIGNAL_HANDLER` for each DIRECT call to a known non-async-signal-safe libc function in its body

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
| Shape | Severity |
|-------|----------|
| Direct call to a non-async-signal-safe function in a registered handler | HIGH |
