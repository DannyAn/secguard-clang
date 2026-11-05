# Feedback-watch capability fixtures (Issue #226)

Reproducible fixtures for the four external defect reports in
[Issue #226](https://github.com/DannyAn/secguard-clang/issues/226). The issue's
`CAT-*` / `CWD-SUB-*` identifiers are kept verbatim; they are external defect
categories, not CWE identifiers.

Each sample is a standalone C translation unit copied from the issue, so the
fixtures can be scanned directly:

```bash
./build.sh
./bin/secguard scan sgre/testdata/feedback_watch/CWD-SUB-1140-uninitialized-condition \
  --db /tmp/fw-1140.db
./bin/secguard scan sgre/testdata/feedback_watch --db /tmp/fw-all.db
```

Measured with `secguard 0.12.2` at commit `0a86648`, single-file scans with
`--context-lines 0`, `Completion State = complete` for every sample (each file
was indexed: functions/lines match the source, no parse failures).

## Capability matrix

| Report | Defect | Status | Detected samples | Missed samples | False positives | Responsible module |
|---|---|---|---|---|---|---|
| CWD-SUB-1029 | pointer offset out of range | **not supported** (target shape) | none | 01, 03, 04 | none | `evidence/buffer_overflow.go` (`detectArrayOOB`, `checkArrayOOB`, `detectUncheckedIndex`) |
| CWD-SUB-1031 | global/shared pointer NULL deref | **partially supported** | 01 | 03 | none (02, 04 clean) | `evidence/null_source.go`, `evidence/dereference.go`, `planner/filter_nullable_source.go` |
| CWD-SUB-1038 | invalid object-pointer cast before capacity check | **not supported** | none | 01, 03, 04 | none | none — no type-size/layout model exists |
| CWD-SUB-1140 | uninitialized read in a condition | **partially supported** | 01, 02, 03, 05 | 07 | none (04, 06 clean) | `evidence/uninit_variable.go`, `planner/filter_uninit_flow.go` |

Statuses use the issue's definitions: *supported* = the core defect sample is
stably detected at the real dangerous operation with a correct evidence chain and
the safe control produces no same-class false positive; *partially supported* =
only some syntax forms / call paths are detected; *not supported* = the core
sample is missed while the scan is complete.

## CWE mapping

| External report | Candidate CWE | Mapped CWE(s) in secguard-clang | Detector / pipeline stage | Actual support |
|---|---|---|---|---|
| CWD-SUB-1029 | CWE-125 / CWE-787 | CWE-125 (out-of-bounds read) / CWE-787 (out-of-bounds write) | `out-of-bounds`, `buffer-overflow` | not supported for the external-offset pointer shape; constant / loop-bound / struct-field index access is covered |
| CWD-SUB-1031 | CWE-476 | CWE-476 | `null-deref` (`null_source` → `nullable_source`) | partially supported — file-scope static NULL pointer is detected; caller-argument → global → deref chain is not |
| CWD-SUB-1038 | CWE-843 (+ CWE-125/787 for the capacity aspect) | CWE-843 is not registered; no type-confusion detector exists | none | not supported |
| CWD-SUB-1140 | CWE-457 | CWE-457 | `uninit` (`uninit_variable` → `definite_init`) | partially supported — scalar/pointer/struct-field/switch-join conditions are detected; output-parameter contracts are not modeled |

## Per-scenario evidence

### CWD-SUB-1029 — pointer offset out of range

- `01_external_offset_oob.c`: `buffer[external_offset]` with the supplied
  `buffer_len` unused → **0 candidates** (`buffer-overflow` and `out-of-bounds`
  both zero). The scan is complete: both functions are indexed.
- `03_wrong_length_check.c`: guard against `packet_len`, access through
  `buffer` → **0 candidates**.
- `04_unsigned_underflow.c`: `dst_len - header_len` unsigned underflow and
  `payload_len - 1` → **0 candidates** (integer-overflow / buffer-overflow).
- `02_validated_offset.c`: correct `offset >= buffer_len` guard → 0 candidates
  (no false positive, but also no detection).

Why: `checkArrayOOB` proves OOB only for constant indices, single-assignment
constant indices, loop bounds, or a heap-allocation size visible inside the same
function. A pointer parameter has no in-function capacity; `buffer[offset]` and
`*(buffer + offset)` are therefore never seeded, and `detectUncheckedIndex`
deliberately excludes plain parameter/local indices (only struct-field-derived
indices reach the heuristic tier). The capability the issue asks for — an
external offset checked against the *target object's* length — requires
call-site capacity binding and a guard-witness test that the checked length is
the object's own length, neither of which exists today.

Minimal fill proposal: build the capacity fact at the call site
(`PARAM_BINDING`/`DATA_FLOW` edges plus `repofacts.GlobalArray`), then in
`checkArrayOOB` treat a callee pointer parameter with a caller-proven capacity
as an array of that capacity; add a suspected-tier category for an index that
is not dominated by a guard on the associated length. Needs a guard-witness
association between `buffer` and its length parameter (name/shape based, must
remain fail-open) before it can avoid flooding normal `buf[i]` parameter code.

### CWD-SUB-1031 — global/shared pointer NULL dereference

- `01_global_pointer_deref.c`: `static struct Session *g_session = NULL;`
  dereferenced in `get_session_state` → **1 candidate** (`null-deref`,
  `get_session_state:11`, variable `g_session`, tier `global-null`, suspected).
  This is the capability added by this change: a file-scope `static` pointer that
  is initialized to NULL (explicitly or by static zero-initialization) and is
  never reassigned anywhere in its translation unit seeds a `NULL_VALUE`
  (`origin=global_null`) for every function that dereferences it.
- `02_null_guarded_deref.c`: local alias + NULL guard → 0 candidates (clean).
- `03_interprocedural_global_deref.c`: `g_session = session` (from a parameter)
  then dereferenced in another function → **0 candidates**. The census that makes
  01 sound also makes 03 unsupported: a non-null write exists, so the global is
  not "only NULL", and the caller-argument nullability is not propagated through
  a global write. This is the documented cross-function global-state gap.
- `04_concurrent_check_then_use.c`: local snapshot + NULL guard → 0 candidates
  (clean, and the local snapshot is correctly not treated as invalidated by
  another thread writing the global). No happens-before / race analysis is
  claimed: the global is written in the tree, so no `global-null` source is
  emitted.

Minimal fill proposal: extend the existing caller-null model with a
global-state summary (function → global write, value nullability) and let
`filter_nullable_source` consume it as a cross-function reaching source. Keep it
at the suspected tier because an external writer or a callable global writer can
invalidate the summary.

### CWD-SUB-1038 — invalid object-pointer cast

- `01_cast_insufficient_size.c`: `malloc(8)` cast to `struct LargeRecord *`,
  then `record->value` → **0 candidates**.
- `03_wrong_target_size_check.c`: `input_len < sizeof(struct SmallHeader)` guard
  before a `struct LargeRecord` access → **0 candidates**.
- `04_element_count_byte_size_confusion.c`: `malloc(count)` then
  `records[count - 1].value` → **0 candidates**.
- `02_cast_sufficient_size.c`: correctly sized allocation → 0 candidates (no
  false positive, but there is also no capability to test).

Why: the codebase has struct *layout* facts (member kinds, pointer/array shape)
but no type-size model and no field-offset model, so "allocated 8 bytes, target
field at offset 16" cannot be expressed. The `memcpy` shape of the same defect
(`memcpy(raw, &tmp, 24)` into `malloc(8)`) **is** detected by
`bounded_copy_overflow`, which shows the gap is type/offset knowledge, not the
buffer-access channel.

Minimal fill proposal: add a `type-size` fact layer (scalar/typedef sizes with
natural alignment, struct field offsets, arrays) and a cast-census detector that
compares allocation capacity to the accessed target field's extent, feeding the
existing `heap_oob_read` / `heap_oob_write` categories. Keep unknown/typedef
sizes fail-open; do not register a new CWE for the type-confusion aspect until
the CWE mapping is agreed.

### CWD-SUB-1140 — uninitialized read in an `if` condition

- `01_uninitialized_scalar_condition.c`: partial-path scalar read →
  **1 candidate** (`uninit:check_state:9`, suspected).
- `02_uninitialized_pointer_condition.c`: `struct Node *node;` read in
  `if (node != 0)` → **1 finding, auto-confirmed** at `check_node:9` plus the
  `node->value` sink at `:10`. Before this change the pointer declarator was
  invisible to the uninit analysis (the declaration loop only registered a
  direct `identifier` child, not the `pointer_declarator` wrapper).
- `03_uninitialized_struct_field.c`: `config.enabled` read while `config.mode` is
  assigned → **1 finding, auto-confirmed** (`check_config:12`); the field-level
  fact is `field@config.enabled`, so the initialized `mode` field is not
  conflated with the uninitialized one.
- `05_partial_switch_init.c`: `default:` path leaves `mode` uninitialized →
  **1 candidate** (`check_mode:16`, suspected); switch-branch join handled.
- `04_initialized_control.c` / `06_static_zero_init.c`: 0 candidates (clean).
  Static-storage zero initialization is correctly not reported.
- `07_outparam_contract.c`: `load_value(&value, success)` writes `*out` only on
  success and the caller ignores the return code → **0 candidates**. The existing
  output-parameter model documents this as a known limitation; it treats the
  `&value` call as initialization without proving the return value was handled.
  (`KnownLimitations` in `planner/registry_uninit.go` already says cross-function
  initialization via output parameters may be missed.)

## Regression coverage

`TestFeedbackWatchCapabilityMatrix` in
`sgre/internal/planner/feedback_watch_test.go` indexes this directory, runs the
`null_source`, `dereference`, `uninit_variable` and `buffer_overflow` detectors,
plans the `null-deref` and `uninit` types, and asserts:

- the four supported uninit samples are reported at the expected
  function/line;
- the guarded/initialized/static-zero controls produce no candidate;
- the file-scope static NULL deref is reported, and the guarded alias control is
  not;
- the two known gap scenarios (CWD-SUB-1029 / CWD-SUB-1038) are asserted to be
  quiet today only through the no-false-positive controls; the gap itself is
  recorded in this README rather than locked into the test, so a future detector
  can start reporting without rewriting a test that encodes the absence.

## Limitations

- The measurements are pipeline-candidate measurements (the pre-AI evidence
  stage). A reported candidate is a lead for AI classification, not a verdict;
  auto-confirmed findings are pipeline-proven.
- The scenario 1 and scenario 3 samples are single-file fixtures. Cross-function
  capacity/type facts and multi-file caller context remain the open work
  described above; this directory does not claim they are supported.
