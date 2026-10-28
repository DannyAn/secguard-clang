---
name: data-representation
description: Classify data-representation evidence — a generic/opaque-pointer consumer misinterprets the object representation the API call established. Default-maps to CWE-843.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-843
  severity: MEDIUM
  domain: contract
---

## Opaque/Generic Pointer Representation Analysis (CWE-843)

`contract_kind: implicit` — a generic/opaque-pointer API erases an object's
static type to `void *`; the actual object representation is a contract
established at the **call site** (for `qsort`/`bsearch`: `base` + `size`), which
the consumer (comparator/callback) must interpret consistently.

### Core Principle

Judge the consumer **together with its call site, never alone.** A `void *` cast
in isolation proves nothing:

```c
const char *s = *(const char **)a;
```

is correct when the caller sorts `char *items[]` (elements are pointers) and
wrong when the caller sorts `char items[]` (elements are scalars). Confirm the
actual element representation at the API call site before confirming a
mismatch. This pair property is what separates the pattern from a local
cast rule.

### Concept vs Phase-1 coverage

- **Concept (the pattern)**: opaque/generic pointer → API establishes an object
  representation → consumer interprets the opaque pointer → actual
  representation ≠ interpreted representation → contract violation. This one
  skill owns the concept; future `callback(void *)`, opaque context, container,
  and plugin/event-callback APIs extend it rather than spawning a
  `callback-data` skill.
- **Phase-1 detector scope (the current implementation)**: direct
  `qsort`/`bsearch` calls + a **named** comparator that casts a `void *`
  parameter directly + a resolvable base element. Indirect callbacks,
  function-pointer tables, wrappers, typedef-hidden bases, and multi-level deref
  chains are out of scope and never guessed. This scope is an implementation
  limit, not a definition of the pattern.

### Evidence Pattern
A data-representation candidate has:
- **data_representation_mismatch**: a `qsort`/`bsearch` call whose base element
  representation differs from how the comparator casts its `void *` parameter —
  the detail names the comparator, the base variable with its true element type
  (`expected`, e.g. `char`), and the comparator's cast target (`actual`,
  e.g. `char **`)
- **call_path**: the function is reachable from an entry point

Pointer-depth (indirection-level) mismatch is **one strong evidence signal, not
the definition**: confirmation must rest on the actual element representation
versus the comparator's interpretation of the opaque pointer. Depth is the
phase-1 signal; struct-field / object-size mismatches are future signals under
the same pattern.

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `cast@<type>` | the value is explicitly cast to this type at the candidate line | judge the truncation/reinterpretation intent |

The cast token names the reinterpretation; the surrounding statement
(from the `Source` column) states whether width or representation is lost.

### Detection Logic
1. For each function, record how it casts its `void *` parameters
   (`(char **)a` → element is a pointer, `(char *)a` → element is a scalar).
2. For each `qsort`/`bsearch` call, resolve the `base` argument's element type.
3. Compare the base element depth against the comparator's interpretation depth.
4. Emit `DATA_REPRESENTATION_MISMATCH` (category `data_representation_mismatch`)
   when they differ, for the AI agent to confirm the real representation.

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
| `char buf[100]; qsort(buf, 100, sizeof(char), cmp)` where `cmp` does `*(const char **)a` — string bytes read as a `char *` | **confirmed** |
| `char *arr[] = {...}; qsort(arr, n, sizeof(char *), cmp)` with `*(const char **)a` — elements ARE `char *` | **false-positive** (representation matches) |
| `cmp` casts `(const char *)a` against `char buf[]` — element is a scalar | **false-positive** (matches) |
| Comparator is correct for this specific call despite the declared base type (typedef/decay/alias) | **false-positive** (resolve the real element type) |
| Indirect callback / function pointer / unresolved base | **dismissed** (out of phase-1 scope, insufficient evidence) |

### Common False Positives
- The same comparator is correct for OTHER call sites (`char *arr[]`) — judge
  the (call site, comparator) pair, not the comparator alone.
- A `typedef` hides the base's real element type — resolve it before confirming.
- `void *`-holding arrays (`void *arr[]`) sorted with a pointer comparator.

### Fix Suggestions
- For a `char buf[]` sort, use `(const char *)a` (or `strcmp(a, b)`), not
  `*(const char **)a`.
- If elements ARE pointers, declare the base `char *arr[]` (or pass
  `sizeof(char *)`), so `*(const char **)a` is correct.
- Remove the erroneous extra indirection level.

### CWE mapping
`CWE-843` (type confusion) is the **default** mapping for a confirmed
incompatible object-type interpretation in this pattern; the finding context may
warrant a more specific CWE. The mapping is driven by the planner registry, not
re-defined here.

### Severity Matrix

`status` (confirmed / dismissed) and `severity` (low / medium / high /
critical) are independent axes. **Reachability affects the verdict, not the
severity**: an unreachable or insufficient-evidence candidate is `dismissed`
(verdict), never "low severity". `metadata.severity` is the type default, not a
ceiling.

| Shape | Severity |
|-------|----------|
| Incompatible interpretation dereferences / reads / writes outside the actual object representation | HIGH |
| Representation mismatch changes semantics but no memory-safety impact is established | MEDIUM |
| Confirmed but genuinely low-impact by project policy | LOW |
