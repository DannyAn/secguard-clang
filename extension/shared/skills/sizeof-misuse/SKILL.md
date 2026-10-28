---
name: sizeof-misuse
description: Classify sizeof-misuse evidence — sizeof applied to a pointer variable inside a size context. Maps to CWE-467/CWE-468.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-467
  severity: HIGH
  domain: memory
---

## sizeof Misuse Analysis (CWE-467 / CWE-468)

### Evidence Pattern
A sizeof-misuse candidate has:
- **sizeof_misuse**: A `sizeof(ptr)` where `ptr` is a pointer VARIABLE (not `sizeof(*ptr)`, not `sizeof(T)`) consumed as a size argument to `malloc`/`calloc`/`realloc`/`memset`/`memcpy`/`memmove`
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `subject@<name>` | the operand `sizeof` is applied to | the category states whether the result is a pointer width instead of the pointee size |

`subject@` plus the detector category is the verdict basis:
`sizeof_pointer` on a single-level pointer is machine-confirmed; the
ambiguous pointer-to-pointer case stays your judgment.

### Detection Logic
1. Collect pointer variables (declared with `*`), counting pointer levels and the base type
2. Find `sizeof_expression` whose operand is a bare identifier that is a pointer variable
3. Require the sizeof to be consumed by a malloc-family / memset / memcpy-family call
4. Resolve the base type through typedefs (cross-file: `typedef char *cstr_t` in a header counts) to decide the category:
   - `sizeof_pointer` — **confirmed**: `sizeof(p)` on a single-level pointer `T *p` where `T` resolves to a non-pointer (`char *q`, `my_uint *p`). `sizeof(p)` is the pointer width while the call intends `sizeof(*p)` — the classic CWE-467 defect.
   - `sizeof_pointer_ambig` — **suspected** (pipeline prior → AI decides): `sizeof(p)` on a pointer-to-pointer (`T **p`) or a `T *p` whose `T` resolves to a pointer typedef (`cstr_t *s`). Allocating an array of pointers legitimately uses `sizeof(p)`, so the pipeline only tiers it `suspected` and the AI settles confirmed/dismissed.
5. Emit `SIZEOF_MISUSE` otherwise

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
| `sizeof_pointer` (`char *q; malloc(n * sizeof(q))`) — pointer width where `sizeof(*q)` is meant | **confirmed** |
| `sizeof_pointer_ambig` (`char **p; malloc(n * sizeof(p))`) — may allocate pointer slots, or the base is a pointer typedef | **dismissed** — reason over the actual intent |
| `memset(p, 0, sizeof(p))` where `p` is a pointer | **confirmed** (zeroes only a pointer width) |
| `malloc(n * sizeof(*p))` | **false-positive** (correct deref) |
| `malloc(n * sizeof(struct foo))` | **false-positive** (type, not pointer) |

### Common False Positives
- `sizeof(char*)` used intentionally (array of pointers)
- A macro that expands `sizeof(*p)` but is text-matched as `sizeof(p)`

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| `sizeof_pointer` feeding malloc/memset/memcpy (pointer width where object width meant) | HIGH |
| `memset(p, 0, sizeof(p))` — zeroes only a pointer width | HIGH |
| `sizeof_pointer_ambig` (pointer-to-pointer / pointer typedef) | MEDIUM (dismissed) |
