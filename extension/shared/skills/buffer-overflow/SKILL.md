---
name: buffer-overflow
description: Classify buffer overflow evidence — BUFFER_ACCESS events from unsafe memcpy/strcpy/sprintf/strcat calls, array/heap/layout out-of-bounds writes, and format overflow. Maps to CWE-787.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-787
  severity: HIGH
  domain: memory
---

## Buffer Overflow Analysis (CWE-787)

### Evidence Pattern
A buffer-overflow candidate has:
- **BUFFER_ACCESS event**: An unsafe function call (memcpy, strcpy, sprintf, strcat, gets)
- **No bounds check**: No guard checking buffer capacity before the unsafe call
- **Reachable**: The function is reachable from an entry point
- **flow_step**: the CSA-style ordered diagnostic path — `[1] buffer … declared
  at line N (capacity M)` → `[2] the index/copy size … originates at line K` →
  `[3] no bounds check dominates …` → `[N] the access at line L writes past the
  end`. Read top-to-bottom as the trace from definition to sink; the missing
  guard step is the defect, the rest is the evidence. The `call_path` fragment
  carries the concrete cross-function chain (see below).

Detector categories that route to this type:
- `buffer_overflow` — unsafe copy API call (memcpy/strcpy/strcat/gets/...)
- `array_oob_write` — constant index, a constant-valued variable index (`int n = 12; buf[n]`), or a loop bound past a fixed-size array, as a write
- `array_oob_write_unchecked` — suspected tier: a fixed-size struct array member written through a struct-field index with no bounds check at the access (`p->svr[p->actived_index] = ...`); the external/config-index shape, handed to you because the field's range is unknown at the write
- `heap_oob_write` — loop bound provably exceeds a `malloc`/`calloc` size (e.g. `malloc(user_len)` + `i < user_len + 10`)
- `layout_oob_write` — suspected: a pointer cast from a constant-size allocation to a struct, then a field write whose computed `offset+size` exceeds the allocation (CWD-SUB-1038). The layout uses the default ABI in Phase 1 (`assumed_default_abi` provenance), so judge the embedded `struct_layout`/`field_access`; a packed/custom-ABI layout or typedef resolution can explain the discrepancy.
- `format_overflow` — **confirmed**: `sprintf`/`wsprintf` into a known-capacity buffer whose constant (literal) output length is provably >= capacity
- `format_overflow_var` — suspected: `sprintf`/`wsprintf` into a known-capacity buffer with a non-constant source. Delegate to you: `%d` of a fixed-width value cannot overflow a 64-byte buffer, but a `%s` of an attacker-controlled string can — judge the format specifier and the source's bound.
- `bounded_copy_overflow` — **confirmed**: `strncpy(dst, src, n)` with a constant `n > sizeof(dst)` (provable overflow)
- `bounded_copy_var_size` — **possible**: `strncpy(dst, src, n)` where `dst` is a fixed array and `n` is a caller-influenced parameter (the length may exceed the capacity; reason over the call sites)
- `secure_copy_overflow` — **confirmed**: an Annex K `_s` function (`memcpy_s`/`strcpy_s`/`sprintf_s`/`strncpy_s`/`memset_s`/`asctime_s`/...) given a constant destination-capacity argument larger than the real buffer (`memcpy_s(dst, 100, src, 50)` with `char dst[8]`) — the lying size defeats the "secure" prefix
- `secure_copy_var_size` — **possible**: a `_s` function whose destination-capacity argument is a caller-influenced variable (may exceed the real buffer)
- `secure_constraint_violation` — suspected (reported as CWE-754, not CWE-787): the required size (copy count, or `strlen` of a literal source) exceeds the DECLARED capacity (`memcpy_s(dst, 16, src, 64)` / `strcpy_s(dst, 4, "hello")`). The Annex K constraint handler fires — truncation or abort — so there is no overflow, but the caller is not handling an exceptional condition.
- `secure_scanf_overflow` — **confirmed**: a `scanf_s`/`sscanf_s`/`fscanf_s` `%s`/`%c`/`%[` conversion whose buffer-size argument (constant) exceeds the real buffer (`scanf_s("%s", buf, (rsize_t)100)` with `char buf[10]`)
- `secure_scanf_var_size` — **possible**: a `scanf_s` conversion whose buffer-size argument is a caller-influenced variable

Read-flavored events (`array_oob_read`, `heap_oob_read`,
`array_oob_read_unchecked`) belong to the `out-of-bounds` type (CWE-125), not
this one.

Evidence file fragments:
- **buffer_access**: the access site
- **api**: the unsafe API called
- **buffer**: the destination buffer and its resolved capacity
- **index**: the access index / copy size expression
- **index_source**: the struct field an unchecked write index was read from
  (`array_oob_write_unchecked`)
- **external_bound**: the index's upper bound is NOT provable in code — when an
  external model (config schema / CLI range / protocol contract) guarantees the
  field's range, the disposition is "pending external constraint", not a proven
  overflow
- **shape_cluster** (only when shape-level clustering ran): the same unchecked
  external-index shape (index-source field + capacity) repeats at other sites in
  this file; one verdict covers every listed `function:line`, see
  `## Clustered Sites`
- **element_field**: the pointer-typed member read out of the written element
- **escape**: the callee the out-of-bounds element (or its address) reaches
- **copy_size** / **dst_capacity** / **size_argument**: the copy size, destination capacity, and `_s` size argument for the bounded/secure-copy categories
- **struct_layout**: the cast target struct type and allocation size (layout_oob_write — CWD-SUB-1038)
- **field_access**: the accessed field's offset and size, showing the access end exceeds the allocation
- **call_path**: the function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `buf@<name>` | the buffer being written | the object of the overflow |
| `cap@N` | the buffer's detector-resolved capacity in elements (array declaration or allocation size) | compare `idx@` against this; a guard bound that is a SYMBOL (a config/capability value) does not prove `idx@ < cap@` — compare the configured maximum, and say so if it is not visible in the tree |
| `src-cap@N` | the SOURCE buffer's known capacity in elements | a copy from a bounded fixed-size source into a destination with `cap@ ≥ src-cap@` is bounded — dismiss from the row (`strcpy(g_dst, g_src)` with two fixed arrays of matching or larger destination) |
| `idx@<expr>` | the access index / copy size / declared size argument (the `_s` capacity or required size) | CONSTANT: the detector already proved it reaches past `cap@` (machine-proved, confirm) — VARIABLE (`n`, a parameter): judge its reachable range against `cap@`; a caller-influenced parameter with no clamp is the dangerous case |
| `idx-src@<field>` | the write index is the struct field `<field>`, with no bounds check against `cap@` dominating the write | unvalidated config/input index -> **confirm**; a bounded field or a caller-validated contract -> **dismiss** |
| `external-bound@unverified` | the write index's upper bound is not provable in code | if a named external model (YANG leaf range, CLI value table, bounded nesting template / protocol contract) guarantees the field's range -> **dismissed** (`pending external constraint: <model>`); otherwise -> **confirmed** |
| `shape-cluster@N` | N other sites in the same file share this index-source field and capacity (the same external-bound judgment) | judge ONCE; the verdict covers every site under `## Clustered Sites` |
| `elem-field@<member>` / `oob-escape@<callee>` | the written element's pointer member / the callee the element escapes to | secondary chain facts — the root cause stays the missing bounds check |
| `cwe-chain@CWE-787→CWE-476` | the root-cause chain exported with this candidate: this finding's CWE, then the consequence CWE | state both in `reasoning`; ONE finding — never a second CWE-476 finding for the same defect |

The variable-`idx@` shapes (`bounded_copy_var_size`, `secure_copy_var_size`,
`secure_scanf_var_size`, `format_overflow_var`) are exactly the delegation
cases in the Classification Rules below — the tokens name the destination
(`buf@`), the capacity (`cap@`), and the expression you must range-judge
(`idx@`) without opening the evidence file.

### Safe Function Alternatives (P0 Exclusion)

| Unsafe | Safe Alternative | Notes |
|--------|-----------------|-------|
| `memcpy(dst, src, n)` | `memcpy_s(dst, sizeof(dst), src, n)` | Annex K |
| `strcpy(dst, src)` | `strcpy_s(dst, sizeof(dst), src)` | Annex K |
| `sprintf(buf, fmt, ...)` | `snprintf(buf, sizeof(buf), fmt, ...)` | Check return |
| `strcat(dst, src)` | `strcat_s(dst, sizeof(dst), src)` | Annex K |
| `gets(buf)` | `fgets(buf, sizeof(buf), stdin)` | Never use gets |

### Safe Wrappers (P1 Exemption)

| Wrapper | Guarantee | Why Safe |
|---------|-----------|----------|
| `SafeCopy_copy(dst, src, n)` | Checks `n > dst->capacity` | Bounds checked internally |
| `SafeCopy_strcpy(dst, src)` | Truncates to `capacity - 1` | Bounds checked internally |

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
| Unsafe call + no bounds check + user-controlled size | **confirmed** |
| Unsafe call + bounds check before call (scope covers) | **false-positive** |
| Unsafe call inside safe wrapper | **false-positive** |
| `memcpy` with `sizeof(dst)` as size | **false-positive** |
| `strncpy` with `sizeof(dst) - 1` + null terminate | **false-positive** |
| Array write with constant index >= array size | **confirmed** |
| `array_oob_write_unchecked` + `external-bound@unverified`: the field's range is guaranteed by a named external model (config schema / CLI value table / bounded template) whose maximum fits `cap@` | **dismissed** — `pending external constraint: <model>`; state the model; one verdict covers the `shape-cluster` sites |
| `array_oob_write_unchecked`: struct-field index, no check against `cap@`/its macro on the path to the write, and nothing outside the code bounds it | **confirmed** |
| `array_oob_write_unchecked`: the field is validated (exit on `>= CAPACITY`, positive branch `< CAPACITY`) or provably bounded below capacity | **false-positive** |
| Loop bound provably exceeds array/heap allocation size (write) | **confirmed** |
| `sprintf(dst, ..., var)` into known-capacity `dst`, no size arg | **confirmed** |
| `format_overflow` (constant literal output length >= capacity) | **confirmed** — the detector proved it |
| `format_overflow_var` where the non-constant source is attacker-controlled with no clamp | **confirmed** |
| `format_overflow_var` where the non-constant source is bounded (a small `int`/enum, or `%d` of a fixed-width value) | **false-positive** — cannot exceed the capacity |
| `sprintf` whose destination feeds `system`/`sqlite3_exec`/`CreateProcessA` | **false-positive** for buffer-overflow (injection is the root cause; SQL/command injection covers it) |
| `bounded_copy_overflow` (constant `n > sizeof(dst)`) | **confirmed** — the detector proved it |
| `bounded_copy_var_size` where `n` is a caller-influenced length (argv/getenv/recv length field, network packet length) with no clamp | **confirmed** |
| `bounded_copy_var_size` where `n` is validated by every caller to `<= sizeof(dst)` (clamp, guard, or a bounded `strlen` source) | **false-positive** |
| `bounded_copy_var_size` where `n` is a local counter / loop bound | **false-positive** (should not reach here — the detector only emits the parameter case) |
| `secure_copy_overflow` (constant size > capacity) | **confirmed** — the detector proved it |
| `secure_copy_var_size` where the capacity argument is attacker-controlled with no clamp | **confirmed** |
| `secure_copy_var_size` where the capacity argument is validated by every caller to `<= sizeof(dst)` | **false-positive** |
| `secure_constraint_violation` (required > declared capacity) | **confirmed as CWE-754** — a real correctness defect (the caller does not handle the exceptional condition), NOT an overflow; the `_s` handler truncates/aborts. Report the contract violation, never "writes past the end" |
| `secure_scanf_overflow` (constant buffer-size arg > capacity) | **confirmed** — the detector proved it |
| `secure_scanf_var_size` where the buffer-size arg is attacker-controlled with no clamp | **confirmed** |
| `secure_scanf_var_size` where the buffer-size arg is `sizeof(buf)` or a bounded length | **false-positive** |

**Unit check before comparing `idx@` and `cap@`.** `cap@` is in **elements**; an `idx@` that is a copy size (`memcpy`/`strncpy`/`_s` size argument) is in **bytes**. Convert before comparing (`idx_bytes ≤ cap_elements * sizeof(elem)`). `int arr[10]; memcpy(arr, src, 40)` copies 40 bytes into 10 ints — exactly fits — and must NOT be confirmed.

**Reasoning for `bounded_copy_var_size`**: the pipeline cannot prove the variable
length exceeds the fixed destination, so it delegates reachability to you. Trace
`n` to its source — if it is attacker-controlled (argv, getenv, recv length, packet
header) with no clamp, the overflow is realistic and should be **confirmed**; if it
is a bounded length (strlen of a fixed buffer, a validated/capped length), it is
**false-positive**.

**Reasoning for `secure_copy_var_size`**: the same delegation applies to the `_s`
destination-capacity argument. The `_s` functions are only safe when the size
argument is truthful; a caller-controlled size that can exceed the real buffer is a
real overflow. Trace the size to its source and apply the same attacker-controlled
vs. bounded distinction.

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Bound the copy/index before the sink: `if (n > sizeof(dst))
  return -1;` or `if (index >= array_size) return -1;`, or replace with a sized
  safe call (`memcpy_s(dst, sizeof(dst), src, n)`, `SafeCopy_copy(&buf, src, len)`).
- **Required conditions** — The capacity and the length must come from the same
  source that sized the buffer; when the caller's capacity is not in the context,
  name it as "to confirm" instead of inventing one. Avoid `sizeof(pointer)` where
  the buffer's real capacity is meant, truncating the length to hide the overflow,
  or adding only a NULL check for an out-of-bounds write.
- **Validation** — Confirm the original path is bounded for every input, normal
  behavior is unchanged, and the re-scan no longer reports the location.

### Examples

```c
// CONFIRMED — unbounded copy from an attacker-controlled source into a fixed buffer
char dst[16]; strcpy(dst, argv[1]);

// DISMISSED — bounded copy sized to the destination
char dst[16]; snprintf(dst, sizeof dst, "%s", argv[1]);
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Unsafe write with attacker-controlled length/size, unguarded (`buffer_overflow`, `bounded_copy_var_size`, `secure_copy_var_size`, `secure_scanf_var_size` with a tainted operand) | CRITICAL |
| Proved constant out-of-bounds WRITE (`array_oob_write` / `heap_oob_write` / `format_overflow` / `bounded_copy_overflow` / `secure_copy_overflow` / `secure_scanf_overflow`) | HIGH |
| Non-constant source, caller-influenced but unproven (`format_overflow_var`) | HIGH (dismissed) |
| `secure_constraint_violation` (truncate/abort by the `_s` handler, no actual overflow) | MEDIUM |
