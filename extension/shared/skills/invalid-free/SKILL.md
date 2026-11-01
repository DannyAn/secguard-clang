---
name: invalid-free
description: Classify invalid-free evidence — a deallocator called on a non-heap object or an interior pointer. Maps to CWE-761.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-761
  severity: CRITICAL
  domain: security
---

## Invalid Free Analysis (CWE-761)

### Evidence Pattern
An invalid-free candidate has:
- **invalid_free**: the deallocator call (free / realloc / project deallocator)
  with category `free_stack_object` / `free_global_array` / `free_offset_pointer`
- **heap_base**: the offset pointer's heap base allocation site (F4 only)
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `pointee@stack` | the argument is a stack object (`free(a)`, `free(&local)`, `free(&local.f)`) | a certain invalid free — confirm |
| `pointee@global-array` | the argument is a global array (`free(g_arr)`) | a certain invalid free — confirm |
| `pointee@heap-offset` | the argument is an interior pointer into a malloc block (`free(p+4)`) | a certain invalid free — confirm |
| `base@<file>:<line>` | the heap base allocation site of an offset pointer | confirms the free releases an interior pointer, not the base |
| `free@<line>` | the deallocator call site | verify the statement matches |

Every `pointee@` shape is machine-proved (AST + local/global census + alias
analysis), so the pipeline auto-confirms it. Your role is to verify the
statement matches — in particular, a macro-wrapped argument (a `FREE(p)` whose
`#define` expands to `free(p)` but where `p` is actually a cast of a heap
pointer) is the one shape to check against `## Macro Definition` before
confirming.

### Detection Logic
1. For each deallocator call (free / realloc / project deallocator set), peel
   casts/parentheses off the first argument
2. `free(NULL)` is skipped; a bare pointer variable (`free(ptr)`) is deliberately
   NOT reported (it is the dominant legal idiom)
3. A stack object (`free(a)` local array, `free(&local)`, `free(&local.f)`), a
   global array (`free(g_arr)`), or an interior pointer (`free(&arr[5])`,
   `free(arr+2)`, `free(p+4)` for a malloc base) is emitted
4. Emit `INVALID_FREE` with the pointee kind; every shape is auto-confirmed

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
| `pointee@stack` / `pointee@global-array` / `pointee@heap-offset` (the pipeline proved the argument is non-heap or interior) | **confirmed** |
| a macro-wrapped argument whose expansion casts a genuine heap pointer (`free((T*)heap_ptr)`) | **false-positive** |
| `free(ptr)` on a plain pointer variable | **false-positive** (the detector never emits it) |

The pipeline already proved the argument is not a heap base pointer, so the
`pointee@` row is a confirm. The only real review risk is a function-like macro
whose argument is a cast of a heap base: read `## Macro Definition` before
confirming such a case.

### Common False Positives
- A macro `FREE(p)` that expands to `free((void*)p)` where `p` is actually a
  heap base — the cast must not be read as "address of a local"
- A cast-wrapped legitimate heap pointer alias (rare)
- `free(NULL)` and `free(ptr)` are already suppressed at the detector

### Fix Suggestions
- Release the object with the correct base pointer, not an interior pointer
- Remove the deallocator call on stack/global storage entirely
- Allocate the object on the heap if ownership is genuinely transferred

### Severity Matrix

`status` (confirmed / dismissed) and `severity`
(low / medium / high / critical) are **two independent axes** — never collapse
them into one column. `status` is the *evidence verdict* ("is it real?"),
`severity` is the *impact* ("how bad if real?"). The front-matter
`metadata.severity` is the type's **default** for a typical confirmed finding,
not a ceiling: pick each finding's severity from the table below.

| Severity | Meaning |
|----------|---------|
| CRITICAL | Attacker-reachable code execution / memory corruption, full data or credential compromise, or a live hardcoded secret |
| HIGH     | A certain or realistically-reachable memory-corruption / crash / DoS / auth-bypass / secret-disclosure defect |
| MEDIUM   | A real defect with limited impact (bounded resource leak, non-sensitive info disclosure, edge-case-only trigger) |
| LOW      | Defense-in-depth only, harmless dead code, or a weak-evidence issue that is dismissed |

**Verdicts**: `confirmed` (proved defect) or `dismissed` (everything else —
false positive OR a candidate you could not settle after reading its source).
`dismissed` → `low`.

| Shape | Reachability / exposure | Severity |
|-------|------------------------|----------|
| `pointee@stack` / `pointee@heap-offset` (stack object / interior pointer free) | certain memory-corruption | CRITICAL |
| `pointee@global-array` | certain invalid free of a global | HIGH |
