---
name: resource-leak
description: Classify resource leak evidence — RESOURCE_ACQUIRE events where a file descriptor, socket, or handle is acquired but not released on all paths. Maps to CWE-404.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-404
  severity: MEDIUM
  domain: resource
---

## Resource Leak Analysis (CWE-404)

### Evidence Pattern
A resource-leak candidate has:
- **resource_acquire**: A file descriptor, socket, database handle, or lock is acquired
- **call_path**: The function is reachable from an entry point
- **no resource_release on some path**: No matching release before a function exit

### Detection Signals
- `open()`, `fopen()`, `socket()`, `accept()`, `dup()`, `epoll_create()`, `eventfd()`, `signalfd()`, `timerfd()`, `mkstemp()` → resource acquired
- Lock/semaphore acquirers and initializers (`pthread_mutex_lock`, `pthread_rwlock_init`, `acquire(...)`) → resource acquired
- Out-parameter factories write the handle through an address-of argument (`sqlite3_open(path, &db)`, `fopen_s(&f, ...)`) → resource acquired
- `close()`, `fclose()`, `unlock`, `release`, `destroy`, `disconnect`, `join`, `deinit` → resource released
- `connect()` is **not** an acquirer: it returns a status code, not a new handle
- Missing release in error-handling paths (early return, goto cleanup)

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Acquired + no release on any path | **confirmed** |
| Acquired + released on the success path only, leaked on an error return | **confirmed** (error path leak) |
| Released on all paths | **false-positive** |
| `goto cleanup` label releasing on all paths | **false-positive** |
| RAII pattern / destructor always called | **false-positive** |
| Ownership returned to the caller | **false-positive** (caller owns) |
| Process exits right after the acquire (the OS reclaims the resource) | **false-positive** |
| Whether a release happens elsewhere cannot be settled from this function | **dismissed** |

An **error-path leak is confirmed, not suspected**: the function demonstrably
returns with the handle still open and that error return is reachable, so the
defect is proved. This is the same defect shape the `memory-leak` skill
classifies as confirmed (`malloc` + `free` on the success path only); the two
must never disagree.

### Path-Sensitive Analysis
The key question: is there a path from the acquire to the function exit that does
NOT pass through a release?

```
fd = open(...);          // acquired on every path
if (fd < 0) return -1;   // acquire failed — no resource held, not a leak
ret = connect(...);
if (ret != 0) return -1; // ← LEAK: returns with fd still open  → confirmed
close(fd);               // release only on the success path
```

```
fd = open(...);
if (err) { close(fd); return -1; }   // ← SAFE: released before the error return
close(fd);
```

### Common False Positives
- `goto cleanup` patterns that close on all paths
- Wrapper classes with destructors (RAII)
- Resources passed to caller (ownership transfer)
- Process exit after acquire (OS cleans up)

### Fix Suggestions
- Close on every error path: `if (ret != 0) { close(fd); return -1; }`
- Route every exit through one `goto cleanup` that closes what was acquired
- Prefer the platform's RAII/cleanup attribute over a manual close
- Do not hand a raw handle to a callee whose ownership contract is unclear

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Lifetime / frequency | Severity |
|-------|---------------------|----------|
| One-shot handle acquire, low call frequency / short lifetime | Low | MEDIUM |
| Per-connection / per-request fd or socket leak in a long-lived service | High | HIGH |
| Unbounded fd/handle leak → fd exhaustion / DoS / service restart | Unbounded | CRITICAL |
| Release may happen in a callee (unsettled) | Unsettled | MEDIUM (dismissed; LOW if one-shot) |
