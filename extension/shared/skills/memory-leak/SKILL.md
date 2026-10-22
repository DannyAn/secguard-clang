---
name: memory-leak
description: Classify memory-leak evidence — MEMORY_ALLOC events where an allocated block is lost on some path with no reachable free, escape, or ownership transfer. Maps to CWE-401.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-401
  severity: MEDIUM
  domain: memory
---

## Memory Leak Analysis (CWE-401)

### Evidence Pattern
A memory-leak candidate has:
- **memory_alloc**: an allocation at a source line — `malloc`/`calloc`/`realloc` (raw or cast), an implicit allocator (`strdup`, `asprintf`/`vasprintf`, `getline`/`getdelim`, `realpath(path, NULL)`), or a custom allocator from the project contract; carries the acquire API (`via malloc`)
- **definite** / **conditional**: the CFG reachability verdict — `definite` = no free/escape/transfer is reachable on any path to function exit; `conditional` = released on some paths, trace each error/early-return path
- **call_path**: the function is reachable from an entry point

Released sites never reach you: the pipeline's ReleaseFilter drops a proved-released
allocation before a candidate is written.

The detector marks the seed event `definite=true` when the CFG proves no free/escape/transfer is reachable from the allocation; the planner's leak-proof filter promotes a `definite` candidate to `confirmed`.

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `alloc@N` | the allocation site line | where the ownership starts |
| `leak@definite` | no free/escape/transfer is reachable on ANY path — machine-proved loss | verify the statement matches, then confirm |
| `leak@conditional` | a release channel exists but the CFG proved a leak path bypasses it | trace that error/early-return path against `free@N,M` |
| `escape@none` | no ownership-transfer channel exists anywhere | nothing to weigh — the loss is total |
| `escape@return` | the value is returned to the caller somewhere | the leak path must be a NON-returning path — find it |
| `escape@store` | the value is stored into a non-local (global/parameter/container) somewhere | the leak path must bypass that store — find it |
| `free@N,M` | the release sites that exist but do not cover the leak path | the ## Code Context window covers them |

The decisive split is the escape token plus the leak token:
`escape@none` + `leak@definite` settles the row from the Hint; any channel
token alongside `leak@conditional` names exactly the release the leak path
skips.

**Evidence budget:** the common shapes are row-decidable — `leak@definite` +
`escape@none` → confirm with no open; `leak@conditional` → compare `free@N,M`
with the row's `Source`; `escape@return|store` + `leak@conditional` is the only
shape that needs the `## Code Context` open. Opening every candidate's Evidence
file in a 25-candidate leak type is a budget violation (`evidence_opens ≤ 12`),
not thoroughness: settle what the Hint decides, open for the genuine channel
cases, and list anything still unsettled in `needs_context`.

### Detection Logic
1. Collect allocations: whole-variable `p = malloc(...)` (with or without a cast), implicit result-returning allocators, and output-parameter allocators (`asprintf(&p, ...)`, `getline(&p, ...)`).
2. Collect releases: `free` and deallocators, unwrapping cast/paren (`free((void *)p)`) and following whole-variable aliases (`q = p; free(q)` releases p).
3. Collect ownership transfer / escape: `return p` (including `return (T *)p`), a store to a non-local (`g = p`, `extern ... global_buf = p`, `state->field = malloc(...)` where the base is caller-owned), and escape-call arguments.
4. Per allocation, use the statement CFG to decide whether a leak path exists — a path to exit or to a later overwrite with no intervening release/transfer/escape.
5. If no release/transfer/escape is reachable on any path, mark `definite` (→ confirmed). If release is reachable only on some paths, leave the candidate for the AI as `suspected`.

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| `definite`: no free, escape, or transfer is reachable on any path (or all such lines are dead code) | **confirmed** |
| Leaked on a concrete error path even though other paths release | **confirmed** |
| Freed/escaped/returned on some paths but leaked on others (conditional ownership) | **suspected** (route to AI; the verdict stays binary) |
| A matching release or ownership transfer for the same object exists on all relevant paths | **false-positive** |
| The candidate is an alias release, cast release, escape-to-owner, returned pointer, guarded free, or `goto cleanup` | **false-positive** |
| Whether a release/owner exists cannot be settled from this function (unknown callee semantics) | **dismissed** |

An **error-path leak is confirmed, not suspected**: if the function demonstrably returns on a reachable error path with the block still owned and unreleased, that is the same proved shape as a never-freed allocation. `memory-leak` and `resource-leak` must never disagree on this shape.

### Common False Positives
- Alias release: `int *q = p; free(q);` — releases p's block
- Cast release: `free((void *)p);` — still releases p
- Escape to a non-local owner: `g = (T *)p;` / `extern int *global_buf; global_buf = p;` / `state->in = malloc(...)` where `state` is caller-owned
- Ownership transfer: `return p;` or `return (T *)p;` — the caller now owns it
- Null-guard early return: `if (p == NULL) return -1;` then `free(p)` — the NULL path carries no allocation
- Guarded free: `if (p) free(p);` — skipping the free on the NULL branch is not a leak
- Shared cleanup via `goto cleanup`:

  ```c
  int build_message(int failed) {
      char *buf = malloc(128);
      int ret = 0;
      if (buf == NULL) return -1;
      if (failed) { ret = -2; goto cleanup; }
      use_buffer(buf);
  cleanup:
      free(buf);
      return ret;
  }
  ```

  A label named `cleanup` is not itself proof of release — verify the cleanup is reached on every relevant exit and frees the same object.

- RAII create/destroy pair — but only the returned/transferred allocation is safe; a temporary the create function never returns or frees still leaks
- `realloc` into a different target: `int *tmp = realloc(p, n);` consumes p's block, so p is not lost
- A freed implicit allocator: `p = strdup(s); free(p);`

### Fix Suggestions
- Release on every relevant error path, or route every exit through one `goto cleanup`
- Preserve the original pointer on `realloc` failure: `tmp = realloc(p, n); if (tmp) p = tmp;`
- Do not overwrite the only reference to a live allocation (`p = malloc(); p = malloc();` leaks the first block)
- Do not add `free()` blindly: the pointer may be borrowed, already released, pool-managed, or owned elsewhere (risks double-free / use-after-free)

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict (confirmed/dismissed), `severity` = impact (low/medium/high/critical). `metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Lifetime / frequency | Severity |
|-------|---------------------|----------|
| One-shot leak on a rare path, short-lived process | One-shot | MEDIUM |
| Per-request / per-connection / per-iteration leak in a long-lived service | Repeated | HIGH |
| Unbounded accumulation → memory exhaustion / outage | Unbounded | CRITICAL |
| Leak depends on an unknown callee / ownership unsettled | Unsettled | MEDIUM (dismissed) |