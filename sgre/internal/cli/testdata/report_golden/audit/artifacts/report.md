# SecGuard Security Scan Report

> This report reflects **AI-classified confirmed findings**.
> Only confirmed findings are persisted; dismissed candidates are not recorded. Pipeline candidates are in `candidates/`.

## Scan Overview

| Field | Value |
|-------|-------|
| Scan ID | `sc_2026-11-22_010000_abcdef` |
| Tool | secguard-clang v<VERSION> |
| Target | `<ROOT>/src` |
| Scan time | <TIMESTAMP> |
| Automated analysis | 1.2 s (index + graph + detectors + convergence + auto-confirm) |
| Codebase scale | 2 files / 5 functions / 25 lines |
| Vulnerability types scanned | 5 |
| Scan mode | full |

## Result Summary

**This scan reported 4 confirmed issues. 1 auto-confirmed by the pipeline, 3 classified by the AI.**

| Metric | Value |
|--------|-------|
| Files scanned | 2 |
| Functions scanned | 5 |
| Lines of code | 25 |
| Raw evidence seeds | 24 |
| Converged candidates | 5 |
| Confirmed findings | 4 |
| — proved by the pipeline (auto-confirmed) | 1 |
| — classified by the AI | 3 |
| — auto-confirm verdicts overturned by final review | 1 (50.0% overturn rate) |
| Actionable findings (confirmed) | 4 |
| Vulnerability types with findings | 4 |

### Findings by Severity

| Severity | Confirmed |
|----------|-----------|
| high | 2 |
| medium | 1 |
| low | 1 |
| **TOTAL** | **4** |

## Findings by Skill

| Skill | CWE | Confirmed | Auto-confirmed |
|-------|-----|-----------|----------------|
| buffer-overflow | CWE-787 | 1 | 1 |
| null-deref | CWE-476 | 1 | 0 |
| out-of-bounds | CWE-125 | 1 | 0 |
| unchecked-return | CWE-252 | 1 | 0 |
| **TOTAL** | | **4** | **1** |

## buffer-overflow (CWE-787)

| # | Status | Severity | Function | File:Line | Summary |
|---|--------|----------|----------|-----------|---------|
| 1 | confirmed | high | use_buffer | src/a.c:9 | index n is not bounds-checked against buf[4] |

## null-deref (CWE-476)

| # | Status | Severity | Function | File:Line | Summary |
|---|--------|----------|----------|-----------|---------|
| 1 | confirmed | high | read_value | src/a.c:4 | p is dereferenced without a NULL check |

## out-of-bounds (CWE-125)

| # | Status | Severity | Function | File:Line | Summary |
|---|--------|----------|----------|-----------|---------|
| 1 | confirmed | low | copy_all | src/b.c:4 | strcpy may write past dst |

## unchecked-return (CWE-252)

| # | Status | Severity | Function | File:Line | Summary |
|---|--------|----------|----------|-----------|---------|
| 1 | confirmed | medium | unchecked | src/a.c:19 | p is indexed without validating the callee return |

## Output Files

- SARIF (verdict stage, confirmed only): `result.sarif`
- SARIF (candidate stage, level `note` — unclassified leads): `candidates.sarif`
- Findings to review (confirmed: pipeline auto-confirmed + AI-classified): `findings/<vuln-type>/<NNN>_<file>_<line>_confirmed.md`
- Candidate evidence (pipeline output, pre-classification): `candidates/<vuln-type>/`
- Audit report (pipeline statistics): `audit-report.md`
- Database: `.sgre/sgre.db`
