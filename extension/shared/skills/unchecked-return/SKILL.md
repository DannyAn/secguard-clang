---
name: unchecked-return
description: Classify unchecked-return evidence — an allocation/I/O call whose return value is neither compared nor stored into a checked variable. Maps to CWE-252.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-252
  severity: HIGH
  domain: semantic
---

## Unchecked Return Value Analysis (CWE-252)

### Evidence Pattern
An unchecked-return candidate has:
- **unchecked_return**: A call to `malloc`/`calloc`/`realloc`/`fopen`/`opendir`/`read`/`recv`/`write`/`send` whose value is not compared directly and is not assigned to a variable that is later compared
- **callee_definition**: For a `contract@unknown` candidate, where the callee is defined in the scan (`<file>:<line>`, with signature) and its body embedded under `## Callee Definition` — or an explicit "no definition in the scan" for external/library callees, so you go to API knowledge instead of searching
- **call_path**: The function is reachable from an entry point

### Detection Logic
1. Find calls to the target allocation/I/O functions
2. Skip if the call is directly inside a comparison, `!` negation, or branch/loop condition
3. Skip if the result is assigned to a variable that appears in a `==`/`!=`/`<`/`>` comparison anywhere in the function
4. Emit `UNCHECKED_RETURN` otherwise

### Failure Contract (decisive)

The `Hint` column carries `contract@known` or `contract@unknown` for every
unchecked-return candidate. This is the decisive fact:

| Hint | Meaning | Action |
|------|---------|--------|
| `contract@known` | The callee is a standard unchecked-return API (`malloc`/`fopen`/`read`…), a declared allocator (`secguard.toml [allocators]`), or a body-verified passthrough wrapper. An unchecked return is a genuine CWE-252 defect. | **confirmed** (unless the Source column shows a check the pipeline missed) |
| `contract@unknown` | The callee is an allocator by NAME only (an `alloc` substring, a `*_new`/`*_dup` factory). Its failure behaviour is unproven — it may be pool-, stack- or caller-buffer-backed and never fail. | Prove the callee returns a failure sentinel (`NULL` / `-1` / error code) on the unchecked path. The `Hint` carries `callee@<file>:<line>`; the evidence file embeds the callee body under `## Callee Definition`, so the proof is an in-file judgment — do NOT spend a source READ on a body that is already shown. If the evidence says `none in scan`, the callee is external/library: prove the contract from API knowledge, not from a source READ. If you cannot prove it, **dismiss**. |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `malloc(n)` result dereferenced with no NULL check | **confirmed** |
| `read(fd, ...)` / `recv(...)` return ignored AND the target buffer is used afterward | **confirmed** (a short read / error leaves the buffer uninitialized or partial) |
| `read(fd, ...)` return ignored but the buffer is never used, or a short read is acceptable | **false-positive** |
| `p = malloc(n); if (!p) return;` | **false-positive** (checked) |
| `if (malloc(n) == NULL) ...` | **false-positive** (checked inline) |
| `p = malloc(n); free(p);` — the result's ONLY use is a NULL-safe deallocation | **false-positive** (`free(NULL)` is a no-op; the detector already suppresses this shape, so seeing it means a freeing macro is involved — judge the macro) |
| Every consumer of the result is NULL-safe — an entry-guarded callee (`if (p == NULL) return -1;`, possibly through a cast alias `T *q = (T *)p`), a positively-guarded callee (`if (p != NULL) { ... }`), a void callee that handles NULL internally — with the call result checked (guarding callee) or deliberately discarded (`(void)add(p, x)`) | **false-positive** (consumer census: a NULL result cannot misbehave anywhere; the detector suppresses the in-scan shapes, so seeing this means a consumer is external — judge its NULL contract from API knowledge) |
| The result is stored into a struct field that a shared downstream validator checks (`if (s->field == NULL) return -1;`) | **false-positive** (field escape validated downstream) |
| One consumer is NULL-safe but another dereferences the value | **confirmed** (the census is AND — one unsafe consumer keeps the defect) |

### Common False Positives
- Assignment followed by a check in a macro or helper (`xmalloc` wrappers)
- `read()` used where a short read is acceptable (e.g. `read(fd, &ch, 1)` loops)
- A pointer whose only consumer is `free()` / `cfree()` / `kfree()`
- All consumers entry-guard or positively guard the argument and the results are discarded (`(void)filter_add(f, x)`) or void-internal — a NULL result has no observable consequence
- Out-param allocator (`asprintf`/`vasprintf`/`getline`/`getdelim`) whose target is only handed to a callee, not dereferenced in-function: `asprintf(&err_msg, ...); return fail(error, err_msg, EXIT_FAILURE);`. The return value is a status code, and a failed call leaves the out-param NULL (glibc semantics); the NULL risk belongs to the null-deref chain (the callee's NULL contract, e.g. `fail` handles `msg == NULL` with a default message), never to unchecked-return. The detector already suppresses this shape — it fires only when the out-param is dereferenced in-function without a guard (`asprintf(&p, ...); p[0] = x;`).

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| `malloc`/`calloc` result dereferenced with no NULL check | HIGH |
| `read`/`recv`/`fread` return ignored AND the buffer is used (uninit/partial) | MEDIUM |
| Return ignored but result never used / short read acceptable | LOW |
