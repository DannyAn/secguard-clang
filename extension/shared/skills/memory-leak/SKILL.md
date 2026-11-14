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
- **ref_chain** / **shallow_release** (global-container shallow free): the
  leak is NOT the candidate line's allocation. The leaked block is a
  heap-owning FIELD of an object a global container owns, and the deletion path
  released the outer object without releasing the field, then cleared the slot
  — the chain is `container slot -> object -> object->field`. `ref_chain` is
  the full reachability chain; `shallow_release` names the outer release that
  left the field unreleased; `memory_alloc` carries the field's allocation and
  the store that attached it.

Released sites never reach you: the pipeline's ReleaseFilter drops a proved-released
allocation before a candidate is written. An allocation stored into a wrapper
object that escapes the caller is re-homed by a `container_transfer` release and
is reported (if at all) at the object's deletion path, not at the allocation.

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
| `free-mismatch@<api>` | a release exists but frees the WRONG allocator family (`free()` on an XPath context, `cJSON_Delete` on a `strdup` block) | the call does NOT release this object — it is a leak (and a latent invalid-free); confirm the leak |
| `transfer-cond@<guard>` | an ownership transfer is CONDITIONAL (only on some branch) | the branch that skips the transfer is the leak path — judge whether that branch is reachable |
| `free-on-borrow@<api>` | the release targets a BORROWED pointer (`cJSON_Delete` on `cJSON_GetObjectItem`'s result, `free` on `strstr`'s) | an invalid free of an object owned elsewhere, NOT a leak — dismiss the leak |
| `container-field@<slot>-><obj>-><obj>-><field>` | the leaked block is reachable ONLY through this global-container chain; the deletion path freed the outer object without freeing this field and then cleared the slot | confirm when the Code Context shows the release path has no field release; dismiss only when a destructor that frees the field is reachable on that same path |
| `shallow-free@<api>:<line>` | the outer object's release call that did NOT free the leaked field | check the Code Context + `## Callee Definition` — a helper that frees the field would have suppressed the candidate |
| `field-alloc@<function>:<line>` | where the leaked field's block is allocated | the fix belongs on the deletion path shown in the Code Context, not at this allocation line |

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

### Global-container shallow free

`g_policy_table[idx] -> policy -> policy->cfg` is a complete defect shape when
the create path allocates `cfg`, stores it into `policy->cfg`, and a wrapper
(or a direct store) puts `policy` into the global container, while the deletion
path frees the outer object and clears the slot. Two functions and an object
graph separate the allocation from the loss, so the pipeline reports it at the
SLOT-CLEAR line of the deleting function, with `container-field@` carrying the
chain. Judge it from the row: a field release on that path (a direct
`free(obj->field)`, a deep release helper, or an alias release) would have
suppressed the candidate; the absence of such a release, plus the field's own
allocation witness, is the defect. The `T *g[N]` array form, the `T **g` form
and the single-pointer `T *g` form are all modelled.

### Third-party orphan objects

A cJSON / libxml2 object created but never attached to a parent before an early
exit leaks: `item = cJSON_CreateObject(); if (cond) return; cJSON_AddItemToArray(arr, item);` — the `return` drops `item`. Audit every
`cJSON_Create*` / `xmlNewNode` / `xmlNewDoc` site for a `break`/`return`/`goto`
between creation and the attach call; the attach is the release channel, so a
path that bypasses it is the leak.

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
| `definite`: no free, escape, or transfer is reachable on any path (or all such lines are dead code) | **confirmed** |
| Leaked on a concrete error path even though other paths release | **confirmed** |
| `p = realloc(p, n)` where the failure path (`if (!p) return;`) loses the original block | **confirmed** — the old block is overwritten before the check; preserve it in a temp first (`tmp = realloc(p, n); if (tmp) p = tmp;`) |
| Freed/escaped/returned on some paths but leaked on others (conditional ownership) | judge the leak path; the verdict stays binary — **confirmed** when a reachable path loses the block without release, **false-positive** when every path releases/escapes |
| A matching release or ownership transfer for the same object exists on all relevant paths | **false-positive** |
| The candidate is an alias release, cast release, escape-to-owner, returned pointer, guarded free, or `goto cleanup` | **false-positive** |
| Whether a release/owner exists cannot be settled from this function (unknown callee semantics) | **dismissed** only when a callee provably releases it (embedded `## Callee Definition` or a declared `[contracts]` takes-ownership); otherwise list it in `needs_context` — do not dismiss blind |
| `container-field@` + `shallow-free@` + `field-alloc@`: a global-container object's heap field is not released on the deletion path that clears the slot | **confirmed** — the reference chain and the allocation witness prove the field was owned by the released object; the missing field release on that path loses it |

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
- Error-handling ownership transfer (framework `fail` family): `asprintf(&err_msg, ...); return fail(error, err_msg, EXIT_FAILURE);` — the external callee takes ownership of the message/path argument and releases it (`fail` → `free(msg)`, `fail_nc_err` → `free(msg)` + `free(path)`, `*_transapi_comm_with_vrp` → `free(path)`). The shape is "directly returned + the argument is never used afterward", so the caller must NOT free it again — a second `free` would be a double-free. The detector already suppresses this shape; when a case reaches you anyway (a differently-named wrapper, e.g. `report_error`), judge the callee's contract from `## Callee Definition` / API knowledge before confirming a leak.
- Unified-cleanup contract (caller-side): a callee writes into a caller-owned
  struct (`parse(msg, &ctx)`) and on its own failure path does NOT free the
  fields it filled — this is legal when the caller zero-initializes the struct
  (`ctx = {0}`) and routes every failure through one reset/destroy that frees
  every field. The callee's "missing free" is the design, not a leak; confirm
  only when the caller's cleanup does not cover the field.

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Release the allocation on every exit path (route them
  through one `goto cleanup`), and on `realloc` failure keep the original pointer:
  `tmp = realloc(p, n); if (tmp) p = tmp;`. Do not overwrite the only reference to
  a live allocation.
- **Required conditions** — Establish the pointer's ownership before adding a
  `free`: it may be borrowed, already released, pool-managed, or owned elsewhere,
  so an unguarded `free` risks double-free / use-after-free. The fix must cover
  the specific leak path the Reasoning names.
- **Validation** — Confirm every path (success and error) releases exactly once,
  no early return skips the cleanup, and the re-scan no longer reports the
  location.

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict (confirmed/dismissed), `severity` = impact (low/medium/high/critical). `metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Lifetime / frequency | Severity |
|-------|---------------------|----------|
| One-shot leak on a rare path, short-lived process | One-shot | MEDIUM |
| Per-request / per-connection / per-iteration leak in a long-lived service | Repeated | HIGH |
| Unbounded accumulation → memory exhaustion / outage | Unbounded | CRITICAL |
| Leak depends on an unknown callee / ownership unsettled | Unsettled | MEDIUM (dismissed) |