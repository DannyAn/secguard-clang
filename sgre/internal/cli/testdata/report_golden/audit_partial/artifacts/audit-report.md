# SecGuard Audit Report

## Scan Overview

| Field | Value |
|-------|-------|
| Scan ID | `sc_2026-11-22_010000_abcdef` |
| Completeness | **PARTIAL** — AI classification unfinished; this is not a complete scan result |
| Tool | secguard-clang v<VERSION> |
| Target | `<ROOT>/src` |
| Scan time | <TIMESTAMP> |
| Automated analysis | 1.2 s (index + graph + detectors + convergence + auto-confirm) |
| Codebase scale | 2 files / 5 functions / 25 lines |
| Vulnerability types scanned | 6 |
| Scan mode | full |

**This scan reported 4 confirmed issues. 1 auto-confirmed by the pipeline, 3 classified by the AI.**

## Per-Skill Pipeline Statistics

| Vulnerability Type | Seed | Final | Auto-confirmed | AI Confirmed | AI Stage | Filter Efficiency |
|---|---|---|---|---|---|---|
| buffer-overflow | 10 | 1 | 1 | 0 | done | 90% |
| memory-leak | 5 | 1 | 0 | 0 | done | 80% |
| null-deref | 4 | 1 | 0 | 1 | done | 75% |
| out-of-bounds | 2 | 1 | 0 | 1 | done | 50% |
| unchecked-return | 3 | 1 | 0 | 1 | done | 67% |
| use-after-free | 2 | 1 | 0 | 0 | pending | 50% |
| **TOTAL** | **26** | **6** | **1** | **3** | — | **77%** |

## AI Value Summary

| Metric | Value |
|--------|-------|
| Raw evidence seeds | 26 |
| Auto-confirmed by pipeline | 1 |
| Auto-confirmed reviewed-out by final review | 1 |
| Auto-confirm overturn rate (Step 5.5 health signal) | 50.0% |
| Candidates needing AI review (suspected/possible) | 6 |
| AI confirmed (actionable, with fix suggestion) | 3 |
| Actionable findings for human review (confirmed) | 4 |
| Pipeline filter efficiency | 77% |

## Filter Chain Details

### buffer-overflow

- **Seed count:** 10
- **Final count:** 1
- **AI classification:** auto-confirmed=1, confirmed=0, ai_stage_status=done

### memory-leak

- **Seed count:** 5
- **Final count:** 1
- **AI classification:** auto-confirmed=0, confirmed=0, ai_stage_status=done, auto-confirmed reviewed-out=1

### null-deref

- **Seed count:** 4
- **Final count:** 1
- **AI classification:** auto-confirmed=0, confirmed=1, ai_stage_status=done

| Filter | Input | Output | Shrink | Removed |
|---|---|---|---|---|
| **nullable-source** | 4 | 1 | 75% | 3 |
| dedupe | 1 | 1 | 0% | 0 |

**Top shrink:** `nullable-source` — removed 3 candidates (75% of its input).

### out-of-bounds

- **Seed count:** 2
- **Final count:** 1
- **AI classification:** auto-confirmed=0, confirmed=1, ai_stage_status=done

### unchecked-return

- **Seed count:** 3
- **Final count:** 1
- **AI classification:** auto-confirmed=0, confirmed=1, ai_stage_status=done

### use-after-free

- **Seed count:** 2
- **Final count:** 1
- **AI classification:** auto-confirmed=0, confirmed=0, ai_stage_status=pending
