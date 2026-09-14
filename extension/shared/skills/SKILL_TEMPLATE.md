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

**Binary verdict**: there is no `suspected` state — `confirmed` or `dismissed`
only. `dismissed` → `low`.

| Shape | Reachability / exposure | Severity |
|-------|------------------------|----------|
| <proved shape, attacker-reachable> | <taint source, no guard> | CRITICAL / HIGH |
| <proved shape, bounded/local> | <no taint, edge case> | HIGH / MEDIUM |
| <unproved shape> | <origin unsettled> | MEDIUM / LOW (dismissed) |
