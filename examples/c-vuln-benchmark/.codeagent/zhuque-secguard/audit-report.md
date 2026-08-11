# SecGuard Audit Report

**Scan ID:** `2026-08-11_163336_d660`

## Per-Skill Pipeline Statistics

| Vulnerability Type | Seed | Final | AI Confirmed | AI Suspected | AI Dismissed | Filter Efficiency | AI Accuracy |
|---|---|---|---|---|---|---|---|
| buffer-overflow | 30 | 27 | 7 | 0 | 0 | 10% | 100% |
| crypto-misuse | 5 | 5 | 5 | 0 | 0 | 0% | 100% |
| deadlock | 1 | 1 | 1 | 0 | 0 | 0% | 100% |
| double-free | 2 | 2 | 1 | 0 | 0 | 0% | 100% |
| format-string | 1 | 1 | 1 | 0 | 0 | 0% | 100% |
| hardcoded-secret | 3 | 3 | 3 | 0 | 0 | 0% | 100% |
| injection | 8 | 6 | 4 | 1 | 0 | 25% | 100% |
| integer-overflow | 2 | 2 | 1 | 0 | 0 | 0% | 100% |
| memory-leak | 15 | 2 | 1 | 1 | 0 | 87% | 100% |
| null-deref | 93 | 23 | 7 | 0 | 0 | 75% | 100% |
| race-condition | 2 | 2 | 1 | 1 | 0 | 0% | 100% |
| resource-leak | 29 | 5 | 2 | 0 | 0 | 83% | 100% |
| uninit | 17 | 9 | 2 | 0 | 0 | 47% | 100% |
| use-after-free | 3 | 1 | 1 | 0 | 0 | 67% | 100% |
| **TOTAL** | **211** | **89** | **37** | **3** | **0** | **58%** | **100%** |

## Filter Chain Details

### buffer-overflow

- **Seed count:** 30
- **Final count:** 27
- **Filter chain:** `[{"name":"call_reach","input_count":30,"output_count":30},{"name":"safe_function_exclude","input_count":30,"output_count":28},{"name":"bounds_check","input_count":28,"output_count":28}]`
- **AI classification:** confirmed=7, suspected=0, dismissed=0

### crypto-misuse

- **Seed count:** 5
- **Final count:** 5
- **Filter chain:** `[{"name":"call_reach","input_count":5,"output_count":5},{"name":"safe_function_exclude","input_count":5,"output_count":5},{"name":"bounds_check","input_count":5,"output_count":5}]`
- **AI classification:** confirmed=5, suspected=0, dismissed=0

### deadlock

- **Seed count:** 1
- **Final count:** 1
- **Filter chain:** `[{"name":"call_reach","input_count":1,"output_count":1},{"name":"safe_function_exclude","input_count":1,"output_count":1},{"name":"bounds_check","input_count":1,"output_count":1}]`
- **AI classification:** confirmed=1, suspected=0, dismissed=0

### double-free

- **Seed count:** 2
- **Final count:** 2
- **Filter chain:** `[{"name":"call_reach","input_count":2,"output_count":2},{"name":"safe_function_exclude","input_count":2,"output_count":2},{"name":"bounds_check","input_count":2,"output_count":2}]`
- **AI classification:** confirmed=1, suspected=0, dismissed=0

### format-string

- **Seed count:** 1
- **Final count:** 1
- **Filter chain:** `[{"name":"call_reach","input_count":1,"output_count":1},{"name":"safe_function_exclude","input_count":1,"output_count":1},{"name":"bounds_check","input_count":1,"output_count":1}]`
- **AI classification:** confirmed=1, suspected=0, dismissed=0

### hardcoded-secret

- **Seed count:** 3
- **Final count:** 3
- **Filter chain:** `[{"name":"call_reach","input_count":3,"output_count":3},{"name":"safe_function_exclude","input_count":3,"output_count":3},{"name":"bounds_check","input_count":3,"output_count":3}]`
- **AI classification:** confirmed=3, suspected=0, dismissed=0

### injection

- **Seed count:** 8
- **Final count:** 6
- **Filter chain:** `[{"name":"call_reach","input_count":8,"output_count":8},{"name":"safe_function_exclude","input_count":8,"output_count":7},{"name":"bounds_check","input_count":7,"output_count":7}]`
- **AI classification:** confirmed=4, suspected=1, dismissed=0

### integer-overflow

- **Seed count:** 2
- **Final count:** 2
- **Filter chain:** `[{"name":"call_reach","input_count":2,"output_count":2},{"name":"safe_function_exclude","input_count":2,"output_count":2},{"name":"bounds_check","input_count":2,"output_count":2}]`
- **AI classification:** confirmed=1, suspected=0, dismissed=0

### memory-leak

- **Seed count:** 15
- **Final count:** 2
- **Filter chain:** `[{"name":"call_reach","input_count":15,"output_count":15},{"name":"safe_function_exclude","input_count":15,"output_count":13},{"name":"has_release","input_count":13,"output_count":2}]`
- **AI classification:** confirmed=1, suspected=1, dismissed=0

### null-deref

- **Seed count:** 93
- **Final count:** 23
- **Filter chain:** `[{"name":"non_nullable_array_suppress","input_count":93,"output_count":73},{"name":"array_oob_precedence","input_count":73,"output_count":73},{"name":"nullable_source","input_count":73,"output_count":41},{"name":"call_reach","input_count":41,"output_count":41},{"name":"guard","input_count":41,"output_count":35},{"name":"safe_function_exclude","input_count":35,"output_count":25},{"name":"bounds_check","input_count":25,"output_count":25}]`
- **AI classification:** confirmed=7, suspected=0, dismissed=0

### race-condition

- **Seed count:** 2
- **Final count:** 2
- **Filter chain:** `[{"name":"call_reach","input_count":2,"output_count":2},{"name":"safe_function_exclude","input_count":2,"output_count":2},{"name":"bounds_check","input_count":2,"output_count":2}]`
- **AI classification:** confirmed=1, suspected=1, dismissed=0

### resource-leak

- **Seed count:** 29
- **Final count:** 5
- **Filter chain:** `[{"name":"call_reach","input_count":29,"output_count":29},{"name":"safe_function_exclude","input_count":29,"output_count":29},{"name":"has_release","input_count":29,"output_count":5}]`
- **AI classification:** confirmed=2, suspected=0, dismissed=0

### uninit

- **Seed count:** 17
- **Final count:** 9
- **Filter chain:** `[{"name":"call_reach","input_count":17,"output_count":17},{"name":"safe_function_exclude","input_count":17,"output_count":15},{"name":"bounds_check","input_count":15,"output_count":15}]`
- **AI classification:** confirmed=2, suspected=0, dismissed=0

### use-after-free

- **Seed count:** 3
- **Final count:** 1
- **Filter chain:** `[{"name":"call_reach","input_count":3,"output_count":3},{"name":"safe_function_exclude","input_count":3,"output_count":3},{"name":"lifetime","input_count":3,"output_count":1}]`
- **AI classification:** confirmed=1, suspected=0, dismissed=0

