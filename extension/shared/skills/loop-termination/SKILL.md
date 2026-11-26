---
name: loop-termination
description: Classify loop-termination evidence — a loop whose exit condition cannot make progress (never-written variable, no-op update, or a continue that skips the update). Maps to CWE-835.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-835
  severity: MEDIUM
  domain: security
---

## Loop Termination Analysis (CWE-835)

### Evidence Pattern
A loop-termination candidate has:
- **loop_progress**: the loop site and the specific no-progress mechanism
  (category `no_progress` — the exit variable is never written; `zero_step` —
  the only write is a no-op; `continue_bypass` — a `continue` skips the write)
- **exit_condition**: the loop exit condition and the variable it depends on
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `loop-kind@<while|for|do>` | the loop construct | the continue-bypass shape only applies to while/do (a for loop's `continue` still runs the update) |
| `exit-cond@<expr>` | the loop's exit condition | the predicate that must eventually become false |
| `progress@<var>` | the exit-condition variable that must advance | the variable to trace through the loop body |
| `no-write` | the progress variable is never assigned/updated in the loop, and there is no break/return/goto exit | open the Code Context and check whether `var` can change through a channel the pipeline cannot model (an alias, a called function, an external/volatile state) |
| `zero-step@N` | the only write(s) are provable no-ops, first at line N | confirm the update truly cannot change the value (`v = v`, `v += 0`, `v *= 1`) |
| `cont-bypass@N` | a `continue` at line N precedes every progress write | confirm the continue path is reachable and really skips the update |

No shape is auto-confirmed: the pipeline proves only the *local* fact (the
variable is never directly written / written only with a no-op / skipped by a
continue). You must judge whether the variable can still change through a
channel the pipeline cannot follow — a pointer alias, an address-taken call, a
global modified by another thread/callback, or a function side-effect — before
confirming.

### Detection Logic
1. For each `while_statement` / `for_statement` / `do_statement`, resolve the
   exit condition's bare progress variable (a single comparison `v <op> expr`
   or a truth test `v` / `!v`); skip constant-true loops (`while (1)`,
   `for (;;)`, `while (true)`) and compound conditions
2. Track only function-locals (parameters or locals, never globals); skip the
   loop when `&v` (address-of) appears in the body/update
3. If the variable is never assigned/updated in the body/update and there is no
   `break`/`return`/`goto`, emit `LOOP_TERMINATION` with category `no_progress`
4. If every write is a provable no-op (`v = v`, `v += 0`, `v *= 1`, …), emit
   `zero_step`
5. In a while/do loop, if a `continue` precedes every write, emit
   `continue_bypass`
6. All categories are suspected

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
| `no-write` + `progress@<var>` and the Code Context shows `var` is a plain local scalar never written and never aliased, so the loop cannot terminate once entered | **confirmed** |
| `zero-step@N` and the Code Context confirms the write cannot change the value and no other path advances it | **confirmed** |
| `cont-bypass@N` and the Code Context confirms the continue path is reachable and skips the only progress update | **confirmed** |
| the variable is written through a pointer alias, an address-taken call, a global/volatile state modified by another thread, signal or callback, or a called function's side-effect | **dismissed** |
| the loop is a deliberate constant-true loop, event loop, or blocking wait | **false-positive** (the detector never emits it) |
| a `break`/`return`/`goto` inside the loop provides a reachable exit the pipeline did not model | **dismissed** |

### Common False Positives
- An intentional `while (1)` / `for (;;)` / `while (true)` service or event loop
  (the detector skips constant-true conditions)
- A loop whose condition variable is a global or `volatile`, set by a signal
  handler, another thread, or a callback (the detector skips globals and
  address-taken locals)
- A loop that exits via `break`/`return` rather than the condition (the
  detector skips no_progress/zero_step when a `break` is present)
- A progress update the parser cannot see as a direct write (an update through
  a macro, a helper, or a pointer alias)

### Fix Suggestions

Compose a structured, evidence-driven `fix_strategy` per confirmed finding — the
five subsections in `agent-body.md` → "Fix Strategy". Type-specific raw material:

- **Recommended fix** — Advance the exit variable on every loop path: add the
  missing update, move the update so no `continue`/early branch skips it, or
  replace a no-op write with the intended step (`i++`, `offset += len`,
  `node = node->next`). Where the loop must be able to stop, add a guard or a
  bound so an external/bounded condition breaks it.
- **Required conditions** — Identify the one variable the exit condition
  depends on and ensure every path through the body changes it (or exits).
  Watch for error branches and `continue` that return to the header without
  advancing the offset/remaining length.
- **Validation** — Re-scan: the location no longer reports; the loop terminates
  for the boundary inputs (empty / malformed packet, zero remaining length);
  no new out-of-bounds or null-deref was introduced by the added update.

### Examples

```c
// CONFIRMED — the exit variable is never advanced, no break
while (i < n) { process(i); }

// CONFIRMED — the error path continue skips the only advance
while (len > 0) { if (parse() < 0) continue; len -= step; }

// DISMISSED — the flag is set by a signal handler (global, external state)
while (!done) { wait(); }
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
| attacker-reachable parse loop (packet/TLV/offset) that cannot advance on a crafted input | remote input reaches the loop | HIGH |
| a local/state-machine loop that cannot advance on an internal error state | bounded/local trigger | MEDIUM |
| unproved / weak-evidence loop lead | origin unsettled | MEDIUM / LOW (dismissed) |
