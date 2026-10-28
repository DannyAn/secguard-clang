---
name: out-of-bounds
description: Classify out-of-bounds read evidence — BUFFER_ACCESS events with array_oob_read/heap_oob_read categories. Maps to CWE-125.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-125
  severity: HIGH
  domain: memory
---

## Out-of-Bounds Analysis (CWE-125)

### Evidence Pattern
An out-of-bounds candidate has:
- **BUFFER_ACCESS event** with category `array_oob_read` (fixed-size array read
  past its declared size), `heap_oob_read` (loop bound past a
  `malloc`/`calloc` allocation), or `array_oob_read_unchecked` (a fixed-size
  array indexed by a struct field with NO bounds check at the access site — the
  external/config-index shape; heuristic tier)
- The subscript appears on the read side of an expression, e.g.
  `secret = arr[i];` or `sum += buf[i];`
- **out_of_bounds**: the access site (function and line)
- **buffer**: the array being read (`array: <name> (capacity: N elements)` when
  the declared size resolved)
- **index**: the access index expression
- **index_source**: the struct field an unchecked index was read from (the
  `array_oob_read_unchecked` tier)
- **element_field**: the pointer-typed member read out of the indexed element
- **escape**: the callee the out-of-bounds element (or its address) reaches
- **flow_step**: the CSA-style ordered diagnostic path — `[1] buffer … declared
  at line N (capacity M)` → `[2] the index … originates at line K` → `[3] no
  bounds check dominates …` → `[N] the access at line L reads past the end`.
  Read top-to-bottom as the trace from definition to sink; the missing guard step
  is the defect, the rest is the evidence. The `call_path` fragment carries the
  concrete cross-function chain (see below).
- **call_path**: the function is reachable from an entry point

The two tiers are distinct:

| Category | What the detector proved | Your job |
|----------|--------------------------|----------|
| `array_oob_read` / `heap_oob_read` | the index provably reaches past `cap@` (constant / interval `lo >= cap@`) — **machine-proved** | confirm from the row, no source read |
| `array_oob_read_unchecked` | the index is read from a struct field and no bounds check against the capacity dominates the access — **heuristic** | judge the field's real range from the Hint / Code Context |

**The unchecked-external-index chain (CWE-125 -> CWE-476).** A fixed-size array
member indexed by an unvalidated external field is out-of-bounds only when that
field can reach or exceed the capacity, which is exactly what a missing entry
check allows. When the out-of-range element's pointer member is then
dereferenced (`svr[idx].domain` passed to a callee that calls `strlen` on it),
the OOB read is the root cause and the null/wild-pointer dereference is its
consequence. The Hint carries the chain: `idx-src@` (the source field),
`elem-field@` (the pointer member read out of the element), `oob-escape@` (the
callee the element reaches, with the member it dereferences), and
`cwe-chain@CWE-125→CWE-476` (the same chain as machine-readable metadata).
State the chain in the verdict (`reasoning`); the finding stays ONE out-of-bounds
defect (CWE-125) — do not count the downstream dereference as a separate root
cause. The candidate file's `## Vulnerability Chain` section and the SARIF
`cwe_chain` property carry the same fact.

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `buf@<name>` | the array being read | the object of the OOB read |
| `cap@N` | the array's declared size in elements | compare `idx@` against this |
| `idx@<expr>` | the access index expression | CONSTANT: the detector already proved it reaches past `cap@` (machine-proved, confirm); variable: judge its reachable range |
| `idx-src@<field>` | the index is the struct field `<field>`, with no bounds check against `cap@` dominating the access | unvalidated config/input index -> **confirm**; a bounded field or a validated caller contract -> **dismiss** |
| `elem-field@<member>` | the indexed element's pointer member read at the access site | when the index is out of range this pointer comes from out-of-range memory (indeterminate) — the null-deref leg of the chain |
| `oob-escape@<callee>` | the out-of-bounds element (or its address) is passed to `<callee>` | if that callee dereferences a pointer member of the element, the OOB element feeds a null-deref sink — state the CWE-125 -> CWE-476 chain |
| `cwe-chain@CWE-125→CWE-476` | the root-cause chain exported with this candidate: this finding's CWE, then the consequence CWE | state both in `reasoning` (`out-of-bounds ... → null-pointer dereference ...`); it is ONE finding — never write a second CWE-476 finding for the same defect |

A constant `idx@` past `cap@` settles the row from the Hint alone — no
evidence-file open needed. An `idx-src@` row needs the field's contract: read
`## Code Context` for the function's entry guard (or its absence).

**A guard bound that is not a literal is not a capacity proof.** When `cap@N` is
a literal but the loop/entry guard compares the index against a SYMBOL
(`if (section_cnt >= DNAT_POOL_SECTION_NUM) return;`), the two numbers are
independent: the static array is `64`, while the guard bound comes from a
capability/config value (`nat_cap_query_def("dnat_sect_per_pool", 64)`) that a
profile or the Lua/XML spec can raise. Compare the *configured maximum* against
`cap@` — not the default — and state which of the two you used in `reasoning`.
If the symbol's value is not visible in the scan tree, treat the guard as
unproven for capacity purposes and say so (the reviewer then checks the
capability file); do not dismiss on "there is a bounds check".

### Typical Example
```c
int arr[10];
for (int i = 0; i <= 10; i++) {   /* i == 10 is out of bounds */
    secret = arr[i];              /* read past the array */
}
```

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
| Constant index (or a constant-valued variable `int n = 12; arr[n]`) >= array size, or loop bound provably overruns size | **confirmed** |
| `idx-src@` index: the field is external/config-supplied and NO bounds check against `cap@` (or its macro, e.g. `NAME_COUNT`) exists on the path to the access | **confirmed** — the unvalidated index can exceed the array; the capacity symbol is in the Hint |
| `idx-src@` index: a check `field >= CAPACITY` (macro or literal equal to `cap@`) exits before the access, or `field < CAPACITY` wraps the access | **false-positive** — the entry validates the index |
| `idx-src@` index: the field is provably bounded below the capacity (written only from a small enum/constant, or clamped by every writer) | **false-positive** |
| Access guarded by a bounds check covering the read | **false-positive** |
| `sizeof(arr)` usage (not an element access) | **false-positive** |

An index that cannot be proven out-of-bounds AND is not field-derived
(`buf[i]` with an ordinary parameter/local `i`) is **not emitted** — the
unchecked channel is deliberately restricted to external field indices so that
the ordinary loop/parameter shape does not flood the review queue.

### Fix Suggestions
- Change the loop to `i < arr_size` or `i <= arr_size - 1`
- Check the index against the allocation size before dereferencing
- Use `snprintf`-style sized APIs when reading from formatted buffers
- Validate an external index at the entry, before any array access:
  `if (p->actived_index >= COUNT) { return CONTINUE; }` — the check must use the
  array's real capacity (the same macro/constant its declaration uses)
- Do not paper over the chain by null-checking the element's pointer member: the
  element itself is out of range, so the bounds check is the fix

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Provable OOB read of adjacent memory (info disclosure) | HIGH |
| OOB read leaking a sensitive adjacent buffer (secrets / canary) | CRITICAL |
| Unchecked external index (`idx-src@`) into a fixed-size struct array, element pointer member dereferenced downstream (`oob-escape@`) | HIGH — the missing bounds check is the root cause, the null-deref is the crash path |
