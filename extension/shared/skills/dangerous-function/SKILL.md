---
name: dangerous-function
description: Classify dangerous-function evidence — a call to a banned libc/runtime function or a non-safe API that must be replaced (CWE-676).
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-676
  severity: MEDIUM
  domain: security
---

## Dangerous Function Analysis (CWE-676)

### Evidence Pattern
A dangerous-function candidate has:
- **dangerous_function**: the banned call with its `category` (see the category table below)
- The event's `variable` is the banned function called (`memcpy`, `strcpy`, `exit`, `atoi`, ...)
- The event's `replacement` is the mandated safer API (best-effort)
- **call_path**: The containing function is reachable from an entry point

### Detection Logic
1. Find every call to a function in the ban table
2. The table = a built-in layered set (below), PLUS the project's
   `secguard.toml` `[banned_functions]` `names` (category `config_banned`)
3. Emit `DANGEROUS_FUNCTION` for each call site, tagged with its category
4. `exit` / `ExitProcess` / `pthread_exit` / `ExitThread` are only reported
   OUTSIDE the program entry point (main/wmain/WinMain/wWinMain)
5. `inet_addr` with a compile-time-constant argument is suppressed (no
   injection / INADDR_NONE confusion without a runtime-controlled value)

### Categories

| Category | Banned functions | Replacement |
|----------|------------------|-------------|
| `process_exit` | `exit`, `ExitProcess` (non-entry only); `pthread_exit`, `ExitThread` (non-entry only); `atexit`, `abort` | return / graceful shutdown / explicit release |
| `stack_allocation` | `alloca` | `malloc`/`free` or a fixed-size buffer |
| `nonlocal_jump` | `setjmp`, `longjmp` | return-value error propagation |
| `unsafe_memory` | `memcpy`, `wmemcpy`, `memmove`, `wmemmove`, `memset` | `memcpy_s`, `memmove_s`, `memset_s`, ... |
| `unsafe_string` | `strcpy`, `wcscpy`, `strncpy`, `wcsncpy`, `strcat`, `wcscat`, `strncat`, `wcsncat` | `strcpy_s`, `strncpy_s`, `strcat_s`, ... |
| `unsafe_format` | `sprintf`, `swprintf`, `vsprintf`, `vswprintf`, `snprintf`, `vsnprintf` | `sprintf_s`, `snprintf_s`, `vsnprintf_s`, ... |
| `unsafe_scan` | `scanf`, `wscanf`, `vscanf`, `vwscanf`, `fscanf`, `fwscanf`, `vfscanf`, `vfwscanf`, `sscanf`, `swscanf`, `vsscanf`, `vswscanf`, `gets` | the `_s` variants (`scanf_s`, `sscanf_s`, ...) / `fgets` |
| `unchecked_conversion` | `atoi`, `atol`, `atoll`, `atof` | `strtol`, `strtoll`, `strtod` (check errno + endptr) |
| `unsafe_alloc` | `realloc` | `malloc` + copy + `free` (project policy) |
| `assert_usage` | `assert` | validate caller input and return an error |
| `insecure_temp` | `mktemp`, `tmpnam`, `tmpnam_r` | `mkstemp` |
| `obsolete_api` | `gethostbyname`, `gethostbyaddr` | `getaddrinfo`, `getnameinfo` |
| `obsolete_api_conditional` | `inet_addr` | `inet_pton` |
| `config_banned` | project names from `[banned_functions]` | project-defined |

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
| A call to a banned function (any category) | **suspected** — the pipeline no longer auto-confirms; you judge the CONTEXT from the hint + Code Context (see below) |
| `api@<fn>` where the function is UNBOUNDED (`strcpy`/`strcat`/`sprintf`/`vsprintf`/`gets`/`scanf`) | **confirmed** — no size argument, the function is dangerous by construction (unless the Source/Code Context shows a fixed, safe destination) |
| `api@memcpy`/`memmove`/`memset` + `size-kind@const` | **dismiss** — a compile-time-constant size is bounded; only confirm when the constant provably exceeds the destination |
| `api@memcpy`/`memmove`/`memset` + `size-kind@var` | **suspected** — judge the bound: read the embedded Code Context ±8 lines for the guard (`if (n > cap) return;`); confirm when the size is caller-controlled and unguarded, dismiss when guarded or the destination is clearly larger |
| A call to `assert` (`assert_usage`) | **suspected** — the AI decides whether it guards caller input (defect) vs an internal invariant (fine) |
| A call to `inet_addr` (`obsolete_api_conditional`) | **suspected** — its risk is conditional on the argument's provenance and the `INADDR_NONE` check, so you must decide: `dismiss` when the argument is not caller-controlled (an internal config field, an already-parsed protocol value, a constant) or when the result is tested against `INADDR_NONE` / `(in_addr_t)-1`; `confirm` when a caller-supplied string is converted and the sentinel is not checked |
| `exit`/`ExitProcess`/`pthread_exit`/`ExitThread` inside the entry point | **false-positive** (the detector never emits it) |
| `inet_addr(<constant>)` | **false-positive** (the detector never emits it) |
| A call to a function NOT in the ban table | **false-positive** (the detector never emits it) |

The banned MEMORY functions (clauses below) are the exception: the project
security guideline allows them when no externally controlled data is involved
and the operation is provably local, so the DETECTOR does not emit them at all —

1. initializing a fixed-length array or struct (`memset(buf, 0, sizeof(buf))`,
   `memset(&s, 0, sizeof(s))`);
2. initializing caller memory when the function takes the pointer AND its size
   (`void init(void *p, size_t n) { memset(p, 0, n); }`);
3. initializing right after a heap allocation (`p = malloc(n); memset(p, 0, n)`
   — the size must be the pointee's `sizeof` or the allocation's own size
   expression, and the allocation must be the variable's last write before the
   call);
4. a copy sized from the SOURCE (`memcpy(dst, src, sizeof(*src))`,
   `memcpy(dst, src, strlen(src))` / `strlen(src) + 1`);
5. a copy whose source is static string data (`strcpy(dst, "abc")`,
   `strcat(dst, SOME_STRING_MACRO)`, `memcpy(dst, "abc", sizeof("abc"))`).

Clause 5's destination must still have room — that is the programmer's check,
and the buffer-overflow / out-of-bounds detectors independently report a
destination that is too small. Anything OUTSIDE these shapes (a literal size
that is not the object's `sizeof`, a copy size taken from an unrelated
parameter, a non-static source) stays a policy finding:

| Shape | Verdict |
|---|---|
| `memset(buf, 0, 64)` on `char buf[16]` | **confirmed** (size is not the object's extent; the overflow is reported separately) |
| `memcpy(dst, src, n)` with an unrelated, caller-controlled `n` | **confirmed** (size-kind@var + unguarded) |
| `memcpy(dst, src, n)` with `n` guarded (`if (n <= sizeof dst)`) | **dismiss** (the Code Context shows the guard) |
| `strcpy(dst, src)` with a non-static source | **confirmed** |

The table is a context policy, not a blind name ban: the pipeline emits every
non-exempt call as **suspected** and the hint (`api@` + `size@` + `size-kind@`)
carries the decisive context, so you judge from the row + embedded Code Context
instead of reading the whole file. UNBOUNDED functions are dangerous by
construction; BOUNDED ones are safe when their size is a constant or guarded.
These policy findings intentionally OVERLAP the context-sensitive
`buffer-overflow` / `injection` /
`format-string` detectors: those answer "does THIS call overflow / inject",
while this type answers "is a non-`_s` API used at all". Both are reported.

### Common False Positives
- A codebase that deliberately vendors a banned function (a compatibility
  `free`-wrapper, a project-local `memcpy`) is an intentional policy exception
  to review.
- The deprecated BSD trio (`bzero`, `bcopy`, `bcmp`) is **not** in the default
  table: it has no `_s` counterpart and a project's own banned-function guideline
  routinely omits it, so the tool must not assert that policy. A project that
  bans them adds `[banned_functions] names`, and any project can drop a built-in
  its guideline does not list via `[banned_functions] exclude`.
- `assert` guarding a TRUE internal invariant (`assert(state == RUNNING)`) is
  not a defect — only asserts on caller input / runtime-fallible results are.
- A project that standardizes on the plain functions and provides no `_s` runtime
  may treat the `unsafe_*` categories as informational; disable the type or trim
  `[banned_functions]` at scan time.

### Fix Suggestions
- `gets(buf)` → `fgets(buf, sizeof(buf), stdin)`
- `mktemp(t)` / `tmpnam(t)` → `mkstemp(t)`
- `gethostbyname(n)` / `gethostbyaddr(...)` → `getaddrinfo(...)` / `getnameinfo(...)`
- `inet_addr(s)` → `inet_pton(AF_INET, s, &addr)`
- `memcpy`/`memmove`/`memset` → `memcpy_s`/`memmove_s`/`memset_s`
- `strcpy`/`strncpy`/`strcat`/`strncat` → `strcpy_s`/`strncpy_s`/`strcat_s`/`strncat_s`
- `sprintf`/`snprintf`/`vsnprintf` → `sprintf_s`/`snprintf_s`/`vsnprintf_s`
- `scanf`/`sscanf`/`fscanf` → `scanf_s`/`sscanf_s`/`fscanf_s`
- `atoi`/`atol`/`atoll`/`atof` → `strtol`/`strtoll`/`strtod`
- `exit`/`abort` (outside main) → return an error to the caller
- `alloca` → `malloc`/`free`
- `setjmp`/`longjmp` → return-value error propagation
- `realloc` → `malloc` + copy + `free`

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary
(confirmed/dismissed); dismissed → `low`.

| Category | Severity |
|----------|----------|
| `process_exit` (`abort` / non-entry `exit` / thread exit) | HIGH |
| `stack_allocation` (`alloca`) | HIGH |
| `insecure_temp` (`mktemp` / `tmpnam`) | HIGH |
| `nonlocal_jump` (`setjmp` / `longjmp`) | MEDIUM |
| `unsafe_alloc` (`realloc`) | MEDIUM |
| `obsolete_api` (`gethostbyname`, `gethostbyaddr`) | MEDIUM |
| `obsolete_api_conditional` (`inet_addr`) | LOW |
| `unsafe_memory` / `unsafe_string` / `unsafe_format` / `unsafe_scan` | MEDIUM |
| `unchecked_conversion` (`atoi`, ...) | LOW |
| `assert_usage` (`assert`) | LOW |
| `config_banned` | MEDIUM |
