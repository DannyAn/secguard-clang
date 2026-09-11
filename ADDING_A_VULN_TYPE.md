# Adding a new vulnerability type (the one standard)

Every new detection follows the same 6 steps. The automated guards (a Go
consistency test + `release/check-extension-consistency.py`) fail the build if
any step is skipped, so "just add a detector" can never silently desync the
planner, the skill registry, or the agent skills again.

The single source of truth for the **type list** is
`sgre/internal/planner/registry.go` (`RegisterVulnType`). Everything else
derives from or is cross-checked against it.

## 1. Detector — `sgre/internal/evidence/<type>.go`

Implement the `Detector` interface (`Name`, `Domain`, `Capabilities`, `Detect`)
and emit `<SEED_EVENT>` rows via `emitEvent(...)`. Each event must carry:

- `category` — the defect shape (also the planner's `CategoryConfidence` key).
- `variable` / `expression` — the root-cause identifier.
- `origin` — where the fact came from (used by filters and evidence).

Register it in `sgre/internal/evidence/registry.go` with `RegisterDetector`.

## 2. Planner spec — `sgre/internal/planner/registry.go`

`RegisterVulnType(&VulnTypeSpec{...})` with:

- `Name` — kebab-case, must equal the skill dir name.
- `CWE` — canonical CWE (the single source of truth for CWE mapping).
- `SeedEventType` — the event from step 1.
- `EvidenceType`, `BuildEvidence`.
- `DefaultSuspicion` — **`"suspected"` unless the detector/filter PROVES the
  defect soundly** (a must-analysis, a constant bound, a known list). Never set
  `"confirmed"` for a may-analysis — a confirmed false positive is the one
  thing that must not reach the auto-ticket path.
- `FilterChain` — `"default"` (call-reach + safe-function) unless you add a
  flow filter in `planner.go` `getFilters`.
- `Categories` / `CategoryConfidence` — only when the detector distinguishes
  proved vs unproved shapes (mirror `format_overflow` vs `format_overflow_var`).

## 3. Filter (optional) — `sgre/internal/planner/planner.go`

Add a `case "<name>":` in `getFilters` if the type needs a flow filter. A filter
either DROPS (proves safe) or PROMOTES to `confirmed` (proves defect) — it must
never do a may-analysis promotion.

## 4. Skill registry — `sgre/internal/skills/vuln_type_skill.go`

Add one `{name, domain, description}` entry to `allSkillSpecs`.

## 5. Skill — `extension/shared/skills/<name>/SKILL.md`

Copy `extension/shared/skills/SKILL_TEMPLATE.md`, fill it in. Hard rules
(enforced by `release/check-extension-consistency.py`):

- YAML frontmatter `name:` == the directory name.
- No H1; the title is `## <Type> Analysis (CWE-...)`.
- `### Classification Rules` opens with the `| Condition | Classification |`
  table and names `confirmed` + `false-positive` (`suspected` optional when the
  type has no suspected tier).

## 6. Tests + guard

- Detector test: index a fixture, assert the `<SEED_EVENT>` is emitted for the
  positive case and not for the negative case.
- Planner test: assert the tier (`confirmed` / `suspected`) for each shape.
- The guard `TestVulnTypeSkillConsistency` (in `sgre/internal/skills/`) runs
  automatically and enforces: every `RegisterVulnType` has a SKILL.md, every
  SKILL.md has a registered type, and `allSkillSpecs` matches `planner.AllVulnTypes()`.

## Verify

```bash
cd sgre && go test -buildvcs=false ./...
python3 release/check-extension-consistency.py
```
