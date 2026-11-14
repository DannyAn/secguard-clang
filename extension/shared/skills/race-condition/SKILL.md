---
name: race-condition
description: Classify race condition evidence — TOCTOU (access→fopen), shared-state (lock→unlock→mutate), and classic shared-variable data races in pthread code. Maps to CWE-362.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-362
  severity: HIGH
  domain: concurrency
---

## Race Condition Analysis (CWE-362)

### Evidence Patterns

#### TOCTOU: Filesystem (CWE-362)
- **RACE_CONDITION event** with category `toctou`
- Pattern: `access(path, ...)` check followed by `fopen(path, ...)` / `open(path, ...)`
- Time-of-check to time-of-use window allows symlink attack or file swap

#### TOCTOU: Shared State (CWE-362)
- **RACE_CONDITION event** with category `toctou_shared_state`
- Pattern: `mutex_lock` → `check` → `mutex_unlock` → `mutate`
- Check and mutation not atomic; another thread can change state between unlock and mutate

#### Classic Data Race (CWE-362)
- **RACE_CONDITION event** with category `shared_data_race`
- Pattern: a file-scope variable accessed by two or more `pthread_create` thread functions, with at least one write, and no `pthread_mutex_lock`/`unlock` scope around the access
- Examples: `g_shared_counter++` in two threads, writer/reader pairs on `g_flag`/`g_data`
- The event carries `thread_functions`, `thread_instances` and `write_line` properties

Evidence file fragments (per category):
- `toctou` — **toctou**: the site; **check_call** / **use_call** / **shared_arg**: the check call (e.g. `access`), the later use call (e.g. `fopen`), and the argument shared between them
- `toctou_shared_state` — **shared_state**: the post-unlock write; **lock_scope**: the guarding mutex and its lock/unlock lines
- `shared_data_race` — **data_race**: the access; **thread_functions** / **thread_instances** / **write_line**: the racing threads and the conflicting write
- all — **call_path**: the function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `threads@<fn>` | the thread function(s) accessing the shared data | confirm only when ≥ 2 live instances reach the data (the SAME function started twice counts) |
| `instances@N` | the number of distinct thread instances | `< 2` means no concurrency — false-positive |
| `write@N` | the conflicting write line | ≥ 1 write is required for a data race |
| `mutex@<name>` / `lock@<lo>-<hi>` | the guarding mutex and its critical-section span (toctou_shared_state) | the candidate's write sits OUTSIDE the span — that gap is the defect |
| `check@<fn>→use@<fn>` | the check-then-use pair (filesystem TOCTOU) | confirm when the path can change between check and use; `O_NOFOLLOW`/`fstat(fd)`/a held lock dismisses |
| `arg@<expr>` | the argument checked then used | the value whose change between check and use is the race |

### Safe Patterns (P0 Exclusion)

| Safe Pattern | Why Safe |
|---------------|----------|
| `fopen(path, "r")` directly, check result | No check-then-use window |
| `open(path, O_RDONLY | O_NOFOLLOW)` | Rejects symlinks atomically |
| `fstat(fd, &st)` after `open` | Check on the fd, not the path |
| Lock held through both check and mutation | Atomic check-then-act |

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
| `access()` + `fopen()` on same path, no atomicity | **confirmed** |
| `access()` + `open()` with `O_NOFOLLOW` | **false-positive** |
| Mutate a shared/global variable after releasing a lock | **confirmed** only when the same variable was READ inside the lock and the post-unlock write re-acts on that read (a real check-then-act); **dismissed** when the post-unlock write is unrelated to the locked read |
| Lock held through check + mutate | **false-positive** |
| `access()` + `fopen()` in same function, path is local | **dismissed** (may be safe if path not attacker-controlled) |
| Check-then-act with no shared state | **false-positive** |
| Shared variable, >= 2 pthread threads, >= 1 write, no lock | **confirmed** |
| Shared variable, all accesses inside lock scope | **false-positive** |
| Shared variable accessed by a single thread INSTANCE (one thread function started once, no second live thread reaches it) | **false-positive** (no concurrent access) |
| Shared variable reached by ≥ 2 live thread instances — including the SAME thread function started twice via `pthread_create` | **confirmed** when ≥1 write and no common lock/atomic guards every access |

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Remove the TOCTOU gap or close the shared-state race: for
  files, replace `access()`+`fopen()` with a direct `fopen()`/`open(O_NOFOLLOW)`
  and error check, `fstat()` the opened fd instead of `stat()` the path, and use
  `flock`/`fcntl(F_SETLK)`; for shared globals, hold the mutex through both the
  check and the mutation.
- **Required conditions** — Every reader/writer of the shared state or file must
  take the same lock; unlocking between check and use re-opens the race. Confirm
  the exact interleaving the finding names before choosing the lock granularity.
- **Validation** — Confirm the check and the use are atomic under one lock (or a
  single fd), run ThreadSanitizer, and re-scan to confirm the location no longer
  reports.

### Examples

```c
// CONFIRMED — two live threads write the same global with no common lock
void t1(void *a) { (void)a; g_counter++; }
void t2(void *a) { (void)a; g_counter++; }

// DISMISSED — the write is inside a critical section
pthread_mutex_lock(&m); g_counter++; pthread_mutex_unlock(&m);
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Shared-data race (≥2 threads, ≥1 write, no lock) → memory corruption / UB | HIGH |
| TOCTOU filesystem (`access`→`open`/`fopen`) on an attacker-influenced path | HIGH (CRITICAL if it crosses a privilege boundary) |
| TOCTOU shared-state (check-then-act split across unlock) | MEDIUM (dismissed) |
| `access()`+`fopen()` where the path is local/trusted | MEDIUM (dismissed) |
