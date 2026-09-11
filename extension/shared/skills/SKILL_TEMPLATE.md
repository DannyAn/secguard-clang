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
| <needs-out-of-scope-facts shape> | **suspected** |
| <provably-safe shape> | **false-positive** |

### Common False Positives
- <a guard/contract that proves safety>

### Fix Suggestions
- <paste-ready fix>

### Severity Matrix
| Shape | Severity |
|-------|----------|
| <proved shape> | <HIGH/MEDIUM> |
| <unproved shape> | <MEDIUM/LOW> (suspected) |
