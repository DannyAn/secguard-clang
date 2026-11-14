---
name: uninit
description: Classify uninitialized variable evidence — VALUE_USE events where a local variable is read before any assignment on some execution path. Maps to CWE-457.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-457
  severity: MEDIUM
  domain: memory
---

## Uninitialized Variable Analysis (CWE-457)

### Evidence Pattern
An uninit candidate has:
- **uninit_use**: A local variable or struct field is read before any assignment
- **declaration** / **allocation**: Where the variable is declared (or heap-allocated and left uninitialized)
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `certain-uninit` | three layers converged — the read is provably uninitialized | verify the statement matches, then confirm |
| `maybe-uninit` | weaker tier — the read may be uninitialized | trace the write paths to the declaration |
| `origin@<kind>` | the uninitialized storage's kind (`stack_uninit`/`heap_uninit`/`struct_partial_uninit`) | where the missing write must be |
| `decl@N` | the declaration line of the uninitialized storage | the ## Code Context window covers it |
| `init@none` | the detector PROVED the read target is never written between declaration/allocation and this read | confirm from the row — no write-path trace needed |
| `init@unseen` | heap/struct storage with no in-function write found, but a cross-function factory / `memset` / output-param may have written it | the pipeline's non-proving weak tier — pre-dismissed by the planner (`uninit_weak_tier`) into the ledger, so it normally does not reach you; if it does (a scan built before this policy), do NOT confirm from the row |
| `init@error-path` + `init-writer@<callee>:<line>` | the interprocedural conditional-uninit evidence: an in-tree callee writes the storage only on some paths (its early return skips the write) and the caller discards the return — the read can see unwritten storage on that error path | the strongest heap/struct uninit tier after `init@none`: read the callee's embedded body / the guard structure in the Code Context, confirm when the read is reachable on the skipped-write path |
| `init@branch` | a write to the read target exists, but only inside a conditional branch (or a conditional dest-writer call) — the read can be reached on the path that skipped it | judge the branch from the Code Context; confirm when the read path does not pass through the write |
| `field@<path>` | the read target is that member/element, NOT the base pointer | check the base object's initialization before confirming the field is uninitialized |
| `init@N` + `may-skip` | the ONLY writes sit inside the loop body starting at line N, and the loop condition may skip them on the first pass | judge the loop condition (covered by the ## Code Context window); nothing else is in scope |

`certain-uninit` settles the row from the Hint; for `maybe-uninit`,
`origin@` + `decl@N` name the storage whose write paths you trace —
and when `init@none`, `init@error-path`, or `init@N` + `may-skip` is present, the
write-path answer is already machine-proven: `init@none` closes the case,
`init@error-path` names the callee's skipped-write path, and `may-skip` reduces
it to the loop condition.

### Detection Signals
- Local variable declared without initializer: `int x;`
- Used before first assignment: `return x;` or `arr[x]` or `if (x > 0)`
- Struct fields used before initialization

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
| Variable read before any assignment on ALL paths | **confirmed** |
| Variable may be initialized on some paths but not all (conditional init) | **confirmed** when the read is reached on a path that skipped the write; **dismissed** only when every path to the read passes through a write |
| Variable initialized before use on all paths | **false-positive** |
| Block-scope `static` / `extern` (zero-initialized by the C standard) | **false-positive** |

### Common False Positives
- Variable initialized implicitly by a command-init macro that does not receive it
  as an argument (`#define CMD_MSG_INIT(recv) do { execId = ...; } while (0)`):
  read the embedded `## Macro Definition`; if the body assigns the variable, dismiss.
  A demoted `init@none` row carrying `macro-context` is exactly this shape.
- Variable initialized via pointer (out-parameter): `init(&x)`
- Variable initialized via `memset(&x, 0, sizeof(x))`
- Variable is a struct with default-zero semantics
- Static variables (zero-initialized by C standard)

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Initialize before the read: at declaration (`int x = 0;`),
  on every branch (`if (c) { x = a; } else { x = b; }`), zero a struct
  (`memset(&s, 0, sizeof(s))`), or `calloc` a buffer that is read before a full
  write.
- **Required conditions** — Every path into the read must write the value first;
  initializing only one branch (or only the declaration) still leaves the other
  paths uninitialized.
- **Validation** — Confirm the value is written before every read on every path,
  normal behavior is unchanged, and the re-scan no longer reports the location.

### Examples

```c
// CONFIRMED — n is read on the path that skipped the write
int n; if (c) n = 1; return n;

// DISMISSED — every path writes before the read
int n = 0; if (c) n = 1; return n;
```

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. The verdict is binary (confirmed/dismissed); dismissed → `low`.

| Shape | Severity |
|-------|----------|
| Uninitialized value used on all paths as control (pointer / index / branch) or leaking stack/heap contents | HIGH |
| Conditionally initialized (only some paths) | MEDIUM (dismissed) |
