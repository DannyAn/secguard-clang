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
- **resource_acquire**: A file descriptor, socket, database handle, or lock is
  acquired — carries the acquire API (`via fopen`) when the call name resolved
- **definite** / **conditional**: the CFG reachability verdict — `definite` =
  no release is reachable on any path from the acquire to function exit;
  `conditional` = released on some paths, trace each error/early-return path
  for a missing close/release
- **call_path**: The function is reachable from an entry point

Released acquires never reach you: the pipeline's ReleaseFilter drops a
proved-released resource before a candidate is written. The detector marks the
seed event `definite=true` when the CFG proves no release is reachable on any
path, and the leak-proof filter promotes a `definite` candidate to `confirmed`.

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `acquire@N` | the acquisition site line | where the ownership starts |
| `leak@definite` | no release/escape/transfer is reachable on ANY path — machine-proved loss | verify the statement matches, then confirm |
| `leak@conditional` | a release channel exists but the CFG proved a leak path bypasses it | trace that error/early-return path against `free@N,M` |
| `escape@none` | no ownership-transfer channel exists anywhere | nothing to weigh — the loss is total |
| `escape@return` | the handle is returned to the caller somewhere | the leak path must be a NON-returning path — find it |
| `escape@store` | the handle is stored into a non-local somewhere | the leak path must bypass that store — find it |
| `free@N,M` | the close/release sites that exist but do not cover the leak path | the ## Code Context window covers them |

The decisive split is the escape token plus the leak token:
`escape@none` + `leak@definite` settles the row from the Hint; any channel
token alongside `leak@conditional` names exactly the release the leak path
skips.

### Detection Signals
- `open()`, `fopen()`, `socket()`, `accept()`, `dup()`, `epoll_create()`, `eventfd()`, `signalfd()`, `timerfd()`, `mkstemp()` → resource acquired
- Lock/semaphore acquirers and initializers (`pthread_mutex_lock`, `pthread_rwlock_init`, `acquire(...)`) → resource acquired
- Out-parameter factories write the handle through an address-of argument (`sqlite3_open(path, &db)`, `fopen_s(&f, ...)`) → resource acquired
- `close()`, `fclose()`, `unlock`, `release`, `destroy`, `disconnect`, `join`, `deinit` → resource released
- `connect()` is **not** an acquirer: it returns a status code, not a new handle
- Missing release in error-handling paths (early return, goto cleanup)

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
