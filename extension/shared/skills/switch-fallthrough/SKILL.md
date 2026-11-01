---
name: switch-fallthrough
description: Classify switch control-flow evidence — a case that falls through or an enum switch missing its default. Maps to CWE-484/478.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-484
  severity: MEDIUM
  domain: security
---

## Switch Fallthrough Analysis (CWE-484/478)

### Evidence Pattern
A switch-fallthrough candidate has:
- **switch_flow**: the fallthrough site or the missing-default switch, with
  category `fallthrough` (a non-empty case whose last statement does not
  terminate) or `missing_default` (an enum switch that does not cover every
  enumerator and has no default)
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

| Token | Meaning | Your action |
|-------|---------|-------------|
| `fall@yes` | the case body is non-empty and its last statement does not terminate | control falls into the next case — judge intent |
| `comment@none` | no exemption comment sits between this case and the next | the pipeline already suppressed documented fallthroughs |
| `case_end@<kind>` | the case's last statement kind | it does not break/return/goto, so the fallthrough is structural |
| `enum@<name>(covered N/M)` | the enum type and its coverage | not every enumerator is covered and there is no default |

Both shapes are heuristics — the pipeline never auto-confirms them. A
`fall@yes` row needs the `## Code Context` to judge whether the next case is an
independent semantic action (confirm) or the same-action continuation of a
ladder (dismiss). An `enum@` row needs you to judge whether the uncovered
members are genuinely unreachable (dismiss) or an externally-controllable value
with no handler (confirm).

### Detection Logic
1. For each `switch_statement`, iterate its `case_statement` children in order
2. A case whose body is non-empty and whose last statement is not
   break/continue/return/goto/noreturn-call, with no `fall through`-style
   comment before the next case, is emitted as `fallthrough`
3. A switch whose condition resolves to an enum type, that covers fewer than all
   enumerators and has no default, is emitted as `missing_default`
4. Emit `SWITCH_FLOW`; both categories are suspected

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
| `fall@yes` + `comment@none` and the next case is an independent semantic action (a command code / message type, not a continuation) | **confirmed** |
| `enum@<name>(covered N/M)` and the uncovered members are externally-controllable with no handler | **confirmed** |
| a same-semantic ladder (e.g. accumulating bits through consecutive cases) | **dismissed** |
| the enum switch's input is normalized/validated upstream, or the uncovered members are unreachable | **dismissed** |
| a `fall through` comment or an int (non-enum) switch without default | **false-positive** (the detector never emits it) |

The pipeline has already applied the comment exemption and the int-switch
suppression, so what remains is still frequently an intentional fallthrough —
the deciding question is whether the two cases are independent semantic actions.

### Common False Positives
- A fallthrough ladder where the cases are consecutive refinements of one action
- An enum switch whose input is validated upstream (the missing members cannot
  reach the switch)
- A `default` that already exists (the detector never emits `missing_default`
  when a default is present, even an empty one)

### Fix Suggestions
- Terminate each case with `break` (or `return`)
- Add an explicit `/* fall through */` comment where the fallthrough is intended
- Add a `default` that handles or rejects unknown enum values

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
| `missing_default` on an externally-controllable enum | attacker can force an unhandled value | HIGH |
| ordinary `fallthrough` | a local control-flow bug | MEDIUM |
