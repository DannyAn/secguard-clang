---
name: loop-bound
description: Classify loop-bound evidence — a loop whose iteration upper bound is externally-controlled or computed by an overflow-prone product. Maps to CWE-606/834.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-834
  severity: MEDIUM
  domain: security
---

## Loop Bound Analysis (CWE-606/834)

### Evidence Pattern
A loop-bound candidate has:
- **loop_bound**: a `for`/`while`/`do` loop whose ascending upper bound is
  `unchecked_input_bound` (a function parameter or an external-input local, with
  no upper-bound guard/clamp) or `bound_mul` (a `var * var` product)
- **loop_bound** (condition): the loop induction variable
- **taint_source**: the bound's external-input origin (`fn:line`), when sourced
  from recv/read/fread/getenv/…
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `loop-kind@<for\|while\|do>` | the loop construct | context for the bound |
| `loop-var@<name>` | the loop induction variable | the LHS of the ascending condition `var < bound` |
| `loop-bound@<expr>` | the loop's upper-bound expression | the value controlling the iteration count |
| `bound-src@<param\|taint>` | where the bound originates | `param` = caller-supplied; `taint` = external input (recv/read/getenv/…) |
| `guard@none-upper` | no upper-bound check/clamp dominates the loop | the pipeline already skipped guarded/clamped loops |

Both shapes are `suspected` — never auto-confirmed. A large or
externally-controlled loop is not a defect by itself; the decisive question is
whether the caller/source can supply a value large enough to cause excessive
iteration (CPU/memory exhaustion), and whether the loop body amplifies the cost.

### Detection Logic
1. For each `for`/`while`/`do` loop, extract the ascending condition
   (`var < bound` / `var <= bound`) and its bound
2. Resolve a named bound through one assignment (`count = n * m`) and classify
   its origin: constant (skip), parameter (`param`), external-input local
   (`taint`), or a `var * var` product (`bound_mul`)
3. Skip when an upper-bound guard (`if (bound > MAX) return;`) or a clamp
   (`bound = min(bound, cap)`) dominates the loop
4. Emit `LOOP_BOUND` for `unchecked_input_bound` (CWE-606) and `bound_mul`
   (CWE-834); constant and local bounds are never emitted

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
| `bound-src@taint` (a network read length/count) + `guard@none-upper` + the loop body performs allocation/copy/IO, and the source is attacker-controlled | **confirmed** (CWE-606 excessive iteration / CPU exhaustion) |
| `bound-src@param` + `guard@none-upper` and a caller can pass an unbounded count into a costly loop | **confirmed** (CWE-606) |
| `loop-bound@a*b` where the operands are caller/attacker-controlled and the product can wrap or reach a huge value | **confirmed** (CWE-834; note the CWE-190 root cause) |
| the source is trusted (a local file descriptor whose length is bounded by the file, a validated config, a protocol-count already range-checked at the caller) | **dismissed** |
| the loop body is a cheap pointer walk / no allocation / bounded work, and the bound is bounded by a documented business limit | **dismissed** |
| an upper-bound guard or clamp that the pipeline did not model (a disjunctive guard, a helper predicate, a bounds check inside the loop body that exits early) | **dismissed** — but do NOT invent one; the `guard@none-upper` fact is a CFG/structural proof of ABSENCE |
| a `while (1)` / `for (;;)` resident loop, a linked-list traversal (`while (p)`), a constant-bounded loop, or a loop with an upper-bound guard/clamp the detector already models | **false-positive** (the detector never emits it) |

The `guard@none-upper` fact is a proof of absence of a MODELLED upper-bound
guard, not of every possible guard — a guard the model cannot see (a helper
predicate, a caller-side range check) is still possible and is exactly what the
Code Context shows.

### Common False Positives
- A `while (1)` / `for (;;)` resident loop (no ascending condition — the
  detector never emits it)
- A loop over a linked list / traversal (`while (p)` — not a countable bound)
- A constant-bounded loop (`for (i = 0; i < 100; i++)`) — never emitted
- A loop whose bound is a parameter but is range-checked at the CALLER
  (the contract is enforced upstream)
- A descending loop (`for (i = n; i > 0; i--)`) — the detector only models
  ascending bounds

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Bound the loop before it runs: range-check the bound
  (`if (count > MAX_COUNT) return -1;`), clamp it (`count = min(count,
  MAX_COUNT)`), or validate the count against the protocol/business limit at the
  trust boundary before it reaches the loop.
- **Required conditions** — `MAX_COUNT` must be the loop's real resource ceiling
  (per-iteration cost × available budget), not a guess; for `bound_mul` also fix
  the product overflow (`if (a > SIZE_MAX / b) return;` or a checked multiply).
- **Validation** — Confirm the bound is validated on every path into the loop,
  oversized inputs are rejected or clamped consistently, and the re-scan no
  longer reports the location.

### Examples

```c
// CONFIRMED — a network length controls the loop with no upper bound, and the
// body allocates (resource amplification)
int n = recv(fd, buf, sizeof buf, 0);
for (int i = 0; i < n; i++) { char *p = malloc(64); /* ... */ }

// CONFIRMED — the iteration count is an overflow-prone product
for (uint32_t i = 0; i < packet_count * multiplier; i++) { process_item(i); }

// DISMISSED — the bound is clamped before the loop
if (count > MAX) count = MAX;
for (int i = 0; i < count; i++) { process(i); }

// DISMISSED — a constant-bound loop (never emitted)
for (int i = 0; i < 100; i++) { process(i); }
```

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
| `bound-src@taint` (network) + costly body (allocation/copy) | attacker-controlled length → CPU/memory exhaustion | HIGH |
| `bound-src@param` + costly body | caller-supplied count, unbounded | MEDIUM / HIGH |
| `loop-bound@a*b` overflow-prone product | caller-controlled operands | MEDIUM |
| cheap-body loop / trusted source | no meaningful resource impact | LOW (dismissed) |
