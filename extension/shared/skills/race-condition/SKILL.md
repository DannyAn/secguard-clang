---
name: race-condition
description: Classify race condition evidence — TOCTOU (access→fopen) and shared-state (lock→unlock→mutate) patterns. Maps to CWE-362.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-362
  severity: HIGH
  domain: concurrency
---

## Race Condition Analysis (CWE-362)

### Evidence Patterns

#### TOCTOU: Filesystem (CWE-362)
- **RACE_CONDITION event** with category `toctou_filesystem`
- Pattern: `access(path, ...)` check followed by `fopen(path, ...)` / `open(path, ...)`
- Time-of-check to time-of-use window allows symlink attack or file swap

#### TOCTOU: Shared State (CWE-362)
- **RACE_CONDITION event** with category `toctou_shared_state`
- Pattern: `mutex_lock` → `check` → `mutex_unlock` → `mutate`
- Check and mutation not atomic; another thread can change state between unlock and mutate

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `fopen(path, "r")` directly, check result | No check-then-use window |
| `open(path, O_RDONLY | O_NOFOLLOW)` | Rejects symlinks atomically |
| `fstat(fd, &st)` after `open` | Check on the fd, not the path |
| Lock held through both check and mutation | Atomic check-then-act |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `access()` + `fopen()` on same path, no atomicity | **confirmed** |
| `access()` + `open()` with `O_NOFOLLOW` | **false-positive** |
| Lock-unlock-mutate with shared variable | **confirmed** |
| Lock held through check + mutate | **false-positive** |
| `access()` + `fopen()` in same function, path is local | **suspected** (may be safe if path not attacker-controlled) |
| Check-then-act with no shared state | **false-positive** |

### Fix Suggestions
- Replace `access()` + `fopen()` with direct `fopen()` and error check
- Use `open()` with `O_NOFOLLOW` to reject symlinks
- Hold the mutex through both check and mutation (don't unlock between)
- Use `fstat()` on the fd instead of `stat()` on the path
- For file locking, use `flock()` or `fcntl(F_SETLK)` for atomic lock+check
- Consider single-threaded design for simple cases