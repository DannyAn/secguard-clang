---
name: <type-name>
description: Classify <type-name> evidence — <one-line: seed event → what it means>. Maps to <CWE>.
license: MIT
compatibility: opencode
metadata:
  cwe: <CWE>
  severity: <HIGH|MEDIUM|LOW>
---

## <Type Name> Analysis (<CWE>)

### Evidence Pattern
A <type-name> candidate has:
- **<seed_event>**: <what the detector emitted, including its `category` value(s)>
- **<supporting_event>**: <any aux event the detector/filter relies on>
- **call_path**: The function is reachable from an entry point

### Hint Tokens (Verdict Basis)

The pipeline precomputes this type's verdict basis into the `_index.md`
`Hint` column and the candidate's `## Verdict Facts` section — document the
tokens your detector/planner emits (registered in
`sgre/internal/planner/hint_tokens.go`):

| Token | Meaning | Your action |
|-------|---------|-------------|
| `<token>@<value>` | <the machine-proven fact it carries> | <what it settles, or the judgment that remains> |

<One paragraph: which token combination settles the row from the Hint
alone, and which shapes still need the `## Code Context`.>

### Detection Logic
1. <step 1 the detector performs>
2. <step 2>
3. Emit `<SEED_EVENT>` with `category: "<category>"` otherwise

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| <provably-a-defect shape> | **confirmed** |
| <needs-out-of-scope-facts shape> | **dismissed** |
| <provably-safe shape> | **false-positive** |

### Common False Positives
- <a guard/contract that proves safety>

### Fix Suggestions
- <paste-ready fix>

### Severity Matrix

`status` (confirmed / dismissed) and `severity`
(low / medium / high / critical) are **two independent axes** — never collapse
them into one column. `status` is the *evidence verdict* ("is it real?"),
`severity` is the *impact* ("how bad if real?"). The front-matter
`metadata.severity` is the type's **default** for a typical confirmed finding,
not a ceiling: pick each finding's severity from the table below, by matching
the **shape** and its **reachability / exposure**.

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
| <proved shape, attacker-reachable> | <taint source, no guard> | CRITICAL / HIGH |
| <proved shape, bounded/local> | <no taint, edge case> | HIGH / MEDIUM |
| <unproved shape> | <origin unsettled> | MEDIUM / LOW (dismissed) |
