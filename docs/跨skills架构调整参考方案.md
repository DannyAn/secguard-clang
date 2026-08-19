# Cross-Skill Funnel Convergence Architecture

\> Comprehensive design extending the null_dereference HYBRID model across all 30 secguard skills.

\> Grounded on IDM production data (4,410 functions, 15,368 calls, 10,724 deref_sites).

---

## 1. Executive Summary

### Problem

Current sgre pipeline across 30 skills shows systematic over-generation:

- **null_dereference**: 4,410 functions → 1,385 candidates → 51 auto_fp → 1,334 AI review (96.3% FP rate)

- **Most skills**: 0-1 auto_fp rules, nearly all candidates go to AI review

- **Token waste**: Workers re-fetch identical function-level facts for every site; same-function sites share 70-90% evidence

- **Scheduling waste**: Function-batched tasks mix high-risk and low-risk sites; backfill gating operates on function count, not site-level risk

### Root Cause

1. **Rule engine gap**: 22/30 skills have zero or one auto_fp rule — the SQL filtering is the only sieve, and it's too broad

2. **Verification unit mismatch**: Current task = batch of function_ids, but the atomic verification question is per-site ("is *this* deref safe?", "is *this* alloc leaked?")

3. **Evidence redundancy**: Worker fetches all function facts for each site; same-function sites share most context

4. **Scope analysis failure**: null_guards.scope_start/scope_end always NULL → guard coverage analysis disabled

### Proposed Architecture

**Site-Batched Task Model**: Task = (function_id, site_ids[]) with pre-fetched Evidence Package.

- **Category A skills** (22/30): site_ids = specific verification sites (deref, alloc, release, buffer_op, etc.)

- **Category B skills** (8/30): site_ids = [] (function-level, no natural site decomposition)

**Evidence Package**: Pre-fetched at plan time, embedded in Worker prompt. Shared facts fetched once per function; site-specific facts fetched per site.

**Extended Rule Engine**: Site-level auto_fp rules (not just function-level), covering patterns like:

- deref-implies-nonnull: prior deref of same var proves non-null

- alloc-then-deref: alloc return deref is always safe (different from null_deref)

- sizeof(*ptr) pseudo-deref: type expression, not runtime deref

### Expected Impact (IDM)

| Metric | Before | After | Reduction |

|--------|--------|-------|-----------|

| null_dereference AI review | 1,334 functions | ~350 sites in ~250 functions | ~74% |

| memory_leak AI review | ~574 functions | ~200 alloc sites in ~150 functions | ~65% |

| Total AI review tokens (all skills) | ~2.1M tokens | ~0.8M tokens | ~62% |

---

## 2. Cross-Skill Verification Unit Taxonomy

### 2.1 Category A: Site-Level Verification (22 skills)

The atomic question is "is THIS SITE safe?" — each site can be independently verified with its own evidence.

| Verification Unit | Skills | Primary Fact Table | IDM Sites | IDM Functions |

|---|---|---|---|---|

| **deref_site** | null_dereference, out_of_bounds, use_after_free | deref_sites | 10,724 | 2,668 |

| **alloc_site** | memory_leak, uninitialized, resource_leak | alloc_sites | 711 | 574 |

| **release_site_pair** | double_free, double_release | release_sites | 1,002 | 538 |

| **alloc+release_pair** | allocator_mismatch, resource_lifecycle, invalid_free | alloc_sites + release_sites | 711+1,002 | 574+538 |

| **buffer_op** | buffer_overflow | buffer_ops | 516 | 402 |

| **lock_op_pair** | lock_misuse, lock_order | lock_ops | 95 | 44 |

| **call_site** | must_check, output_encoding, api_semantic_misuse, error_propagation, refcount_misuse | calls | 15,368 | 3,187+ |

| **var_usage_site** | missing_lock | var_usage | 2,184 | 552 |

| **assignment_site** | ownership_transfer, state_transition | assignments | 5,643 | 1,936 |

### 2.2 Category B: Function-Level Verification (8 skills)

The atomic question is "does THIS FUNCTION contain the pattern?" — no natural site decomposition.

| Pattern | Skills | Detection Method |

|---|---|---|

| **expression_pattern** | assignment_in_condition, operator_precedence, signed_unsigned_compare, suspicious_boolean | AST pattern matching on entire function body |

| **annotation_contract** | nullability_contract, capability_contract | Annotation table + function signature |

| **numeric_overflow** | integer_overflow | Call-site arithmetic analysis |

### 2.3 Key Insight: Category A Dominates

By function count, Category A skills cover the vast majority of candidate surfaces:

- deref_site skills: 2,668 functions (60.5%)

- call_site skills: 3,187+ functions (72.2%+)

- assignment_site skills: 1,936 functions (43.9%)

- alloc_site skills: 574 functions (13.0%)

Category B skills are simpler (AST pattern matching), have fewer candidates, and the current function-level model is already optimal for them.

**Design decision**: Focus site-level optimization on Category A; leave Category B as function-level tasks.

---

## 3. Unified Task Schema

### 3.1 Current Schema

```python

# Current: task = batch of function_ids

verification_task:

task_id: str          # "{scan_id}_{skill_id}_batch{idx:02d}"

candidate_ids: str    # JSON list of function_ids

priority: int         # 1=core, 2=backfill, 3=deep_backfill

```

Problem: Worker receives a list of function_ids and must fetch ALL facts for ALL functions. No site-level filtering. No evidence pre-fetch.

### 3.2 Proposed Schema

```python

# Proposed: task = one function + its verification sites + evidence package

verification_task:

task_id: str          # "{scan_id}_{skill_id}_f{func_id}"

scan_id: str

skill_id: str

function_id: int      # Single function (not a batch)

site_ids: str         # JSON list of site row-ids (empty for Category B)

site_kind: str        # "deref_site" | "alloc_site" | "release_site_pair" | ... | "function"

priority: int         # 1=core, 2=backfill, 3=deep_backfill

evidence_ref: str     # Path to pre-fetched evidence JSON file

status: str           # NEW/DISPATCHED/DONE/FAILED/HELD/SKIPPED

```

### 3.3 Task Granularity Trade-off

| Aspect | Current (function batch) | Proposed (per-function) |

|--------|-------------------------|------------------------|

| Task count (null_dereference) | ~23 tasks (60 funcs/batch) | ~250 tasks |

| Scheduling overhead | Low | Moderate (manageable) |

| Evidence waste | High (re-fetch per Worker) | None (pre-fetched) |

| Site-level filtering | None | Full |

| Backfill precision | Function-level | Site-level |

| Token efficiency | Low (full function source) | High (site-focused evidence) |

**Batching for dispatch efficiency**: The Dispatcher groups per-function tasks into dispatch batches (e.g., 7 concurrent Workers), but each Worker operates on a single function with its site list. This is the same as current Worker behavior (one function at a time) but with pre-fetched evidence.

### 3.4 Evidence Package File

Each task references a pre-fetched evidence file:

```

.codeagent/secguard-cpp-zhuque/.sgre/evidence/{scan_id}/{skill_id}/f{func_id}.json

```

Contents:

```json

{

"function": { "id": 123, "name": "process_msg", "signature": "...", "body_text": "..." },

"file_path": "src/module/process.c",

"params": [

{ "name": "msg", "type_text": "msg_t*", "is_pointer": 1, "position": 0 }

],

"shared_facts": {

"null_guards": [...],

"assignments": [...],

"return_stmts": [...],

"alloc_sites": [...]

},

"sites": [

{

"site_id": 4567,

"site_kind": "deref_site",

"base_var": "msg",

"deref_kind": "arrow",

"access_expr": "msg->data",

"start_line": 42,

"site_specific_facts": {

"nullable_sources": ["param:msg", "alloc:msg=malloc(100)"],

"covering_guards": [],

"prior_derefs": [

{ "line": 30, "expr": "msg->len", "kind": "arrow" }

]

}

}

],

"auto_classification": {

"site_4567": { "classification": "NEEDS_AI", "reason": "No guard covering line 42" }

}

}

```

---

## 4. Evidence Package Architecture

### 4.1 Shared vs Site-Specific Evidence

The evidence package has two layers:

**Shared evidence** (fetched once per function, identical for all sites):

- Function metadata (signature, body_text, is_static)

- Parameters (all params with types)

- Control flow facts (null_guards, return_stmts, goto_labels)

- Data flow facts (assignments, calls within function)

- Resource facts (alloc_sites, release_sites)

**Site-specific evidence** (fetched per verification site):

- The site row itself (from primary fact table)

- Relevant data flow to/from the site

- Guards covering the site

- Prior derefs of the same variable (for deref-implies-nonnull)

- Paired operations (lock/unlock, alloc/free)

### 4.2 Skill Evidence Specification

Each skill declares its evidence requirements via `SkillEvidenceSpec`:

```python

@dataclass

class SkillEvidenceSpec:

skill_id: str

site_kind: str  # "deref_site" | "alloc_site" | ... | "function"

# Shared facts: fetched once per function

shared_tables: list[str]  # e.g., ["null_guards", "assignments", "return_stmts"]

# Site-specific facts: fetched per site

site_tables: list[str]  # e.g., ["deref_sites"] for null_dereference

# Site query: SQL to find sites given a function

site_query: str  # Parameterized SQL with ? for function_id

# Site enrichment: additional per-site queries

site_enrichments: dict[str, str]  # name -> SQL template with ?, ? for function_id, site_id

```

### 4.3 Evidence Specs for All 30 Skills

#### Category A Skills (site-level)

| Skill | site_kind | shared_tables | site_tables | site_enrichments |

|-------|-----------|---------------|-------------|------------------|

| **memory.null_dereference** | deref_site | null_guards, assignments, alloc_sites, params, variables, return_stmts | deref_sites | nullable_sources, covering_guards, prior_derefs |

| **memory.out_of_bounds** | deref_site | null_guards, assignments, alloc_sites, params, variables | deref_sites | nullable_sources, covering_guards, bounds_info |

| **memory.use_after_free** | release_site | null_guards, assignments, alloc_sites, deref_sites | release_sites | post_release_derefs, null_guard_after_release |

| **memory.double_free** | release_site | null_guards, assignments, alloc_sites | release_sites | release_pairs, null_guard_between |

| **memory.invalid_free** | release_site | alloc_sites, params | release_sites | alloc_for_released_var, stack_var_check |

| **memory.memory_leak** | alloc_site | release_sites, return_stmts, goto_labels, assignments, calls | alloc_sites | release_for_alloc_var, cleanup_paths |

| **memory.uninitialized** | alloc_site | assignments, return_stmts | alloc_sites (or variables) | init_before_use |

| **memory.allocator_mismatch** | alloc+release | (none extra) | alloc_sites, release_sites | paired_alloc_release |

| **memory.buffer_overflow** | buffer_op | assignments, alloc_sites, return_stmts, goto_labels | buffer_ops | size_bounds, dest_capacity |

| **resource.resource_lifecycle** | alloc+release | (none) | alloc_sites, release_sites | paired_create_destroy |

| **resource.double_release** | release_site | (none) | release_sites | release_pairs |

| **resource.resource_leak** | alloc_site | release_sites, return_stmts, goto_labels | alloc_sites | release_for_alloc |

| **resource.lock_misuse** | lock_op | return_stmts, goto_labels | lock_ops | paired_lock_unlock |

| **resource.refcount_misuse** | call_site | return_stmts | calls | refcount_ops |

| **concurrency.lock_order** | lock_op_pair | (none) | lock_ops | lock_acquisition_order |

| **concurrency.missing_lock** | var_usage_site | lock_ops, variables | var_usage | shared_var_access, existing_locks |

| **security.input_validation** | deref_site | null_guards, calls, params | deref_sites | tainted_source_trace |

| **security.output_encoding** | call_site | params | calls | output_sink_check |

| **contract.must_check** | call_site | annotations | calls | must_check_annotation, return_value_usage |

| **contract.ownership_transfer** | call_site | (none) | calls | ownership_transfer_pattern |

| **contract.error_propagation** | call_site | return_stmts, goto_labels | calls | error_source, propagation_path |

| **contract.state_transition** | assignment_site | return_stmts | assignments | state_var, valid_transitions |

#### Category B Skills (function-level)

| Skill | site_kind | shared_tables | site_tables |

|-------|-----------|---------------|-------------|

| **memory.integer_overflow** | function | calls | (none) |

| **contract.nullability_contract** | function | annotations, calls, params | (none) |

| **contract.capability_contract** | function | annotations | (none) |

| **semantics.assignment_in_condition** | function | (none) | (none) — AST pattern |

| **semantics.operator_precedence** | function | (none) | (none) — AST pattern |

| **semantics.signed_unsigned_compare** | function | (none) | (none) — AST pattern |

| **semantics.suspicious_boolean** | function | (none) | (none) — AST pattern |

| **semantics.api_semantic_misuse** | function | calls | (none) |

### 4.4 Evidence Size Estimation (IDM)

Based on IDM Fact counts, estimated per-function evidence sizes:

| Skill | Avg Sites/Func | Shared Facts | Site Facts | Total Size |

|-------|---------------|--------------|------------|------------|

| null_dereference | 4.0 derefs | ~15 rows | ~3 rows/site | ~27 rows/func |

| memory_leak | 1.2 allocs | ~10 rows | ~2 rows/site | ~12 rows/func |

| double_free | 1.9 releases | ~8 rows | ~2 rows/site | ~12 rows/func |

| buffer_overflow | 1.3 bufs | ~10 rows | ~2 rows/site | ~13 rows/func |

| must_check | 4.8 calls | ~5 rows | ~1 row/site | ~10 rows/func |

| missing_lock | 4.0 usages | ~3 rows | ~2 rows/site | ~11 rows/func |

**Token estimate**: ~150-300 tokens per fact row → shared=~2,000-4,500 tokens, site-specific=~300-600 tokens/site.

For null_dereference: shared 3,000 + 4 sites × 450 = **4,800 tokens** per function.

Compare to current: Worker reads full function body (~800-1,500 lines × 5 tokens/line = 4,000-7,500 tokens) + all fact queries. Evidence package is comparable or smaller, and eliminates redundant queries.

---

## 5. Site-Level Rule Engine

### 5.1 Current Rule Engine

Rules operate at **function level**: given a function_id, determine if the entire function is auto_fp / auto_tp / low_risk. Implemented as:

- `sql_predicate`: SQL subquery in candidate_query WHERE clause

- `py_predicate`: Python function taking (func_id, db) → bool

- Result: function is either IN or OUT of the candidate set

This is too coarse for site-level analysis. A function may have 5 deref_sites, 3 guarded and 2 unguarded — the function-level rule can't express "mark the 3 guarded sites as auto_fp but keep the 2 unguarded."

### 5.2 Proposed Site-Level Rule Engine

Extend rules to operate at **site level**: given (function_id, site_id), determine the site's classification.

```python

@dataclass

class SiteRuleCheck:

name: str

classification: str  # "AUTO_FALSE_POSITIVE" | "PROVEN_SAFE" | "LOW_RISK"

description: str

predicate_type: str  # "sql" | "py"

sql_predicate: str | None = None   # SQL with ?, ? for func_id, site_id

py_predicate: str | None = None    # Python function name

priority: int = 0

```

### 5.3 Site-Level Rules by Skill

#### memory.null_dereference (7 site-level rules)

| Rule | Classification | Type | Logic |

|------|---------------|------|-------|

| `sizeof_pseudo_deref` | AUTO_FALSE_POSITIVE | sql | deref inside sizeof() is type expression, not runtime deref |

| `deref_implies_nonnull` | PROVEN_SAFE | py | Same variable dereferenced on earlier line → this deref is safe |

| `terminating_guard_covers` | PROVEN_SAFE | sql | Terminating null guard on base_var before this site's line |

| `scope_guard_covers` | PROVEN_SAFE | sql | Non-terminating guard scope_start ≤ line ≤ scope_end |

| `callback_framework` | AUTO_FALSE_POSITIVE | sql | Function name matches callback pattern (function-level, applies to all sites) |

| `caller_null_check` | AUTO_FALSE_POSITIVE | py | All callers null-check before calling (function-level) |

| `public_api_convention` | LOW_RISK | py | Non-static + no callers + no alloc (function-level) |

**Function-level rules** (callback, caller_check, public_api) apply to ALL sites in the function. If any function-level rule fires, all sites are classified accordingly.

**Site-level rules** (sizeof, deref_implies_nonnull, guard_covers) apply to individual sites. A function may have some PROVEN_SAFE sites and some NEEDS_AI sites.

#### memory.memory_leak (5 site-level rules)

| Rule | Classification | Type | Logic |

|------|---------------|------|-------|

| `factory_return` | AUTO_FALSE_POSITIVE | sql | Alloc var returned → ownership transfer |

| `alloc_passed_to_call` | AUTO_FALSE_POSITIVE | sql | Alloc var passed to ownership-transfer function |

| `perfect_cleanup` | PROVEN_SAFE | sql | Every return path has matching release for this alloc |

| `goto_cleanup` | PROVEN_SAFE | sql | Goto cleanup label releases this alloc var |

| `global_static_storage` | PROVEN_SAFE | sql | Alloc assigned to global/static → lifetime exceeds function |

#### memory.double_free (3 site-level rules)

| Rule | Classification | Type | Logic |

|------|---------------|------|-------|

| `null_guard_between` | PROVEN_SAFE | py | Null guard between consecutive releases of same var |

| `single_release_path` | PROVEN_SAFE | sql | Only one release per control-flow path (no overlap) |

| `different_cond_branches` | PROVEN_SAFE | sql | Releases in mutually exclusive if/else branches |

#### memory.buffer_overflow (3 site-level rules)

| Rule | Classification | Type | Logic |

|------|---------------|------|-------|

| `safe_variant_used` | AUTO_FALSE_POSITIVE | sql | Uses _s/_sp safe function variant |

| `size_matches_capacity` | PROVEN_SAFE | sql | Size expr equals allocated capacity |

| `constant_size_within_bounds` | PROVEN_SAFE | sql | Constant size literal ≤ dest buffer size |

#### concurrency.missing_lock (2 site-level rules)

| Rule | Classification | Type | Logic |

|------|---------------|------|-------|

| `local_var_only` | AUTO_FALSE_POSITIVE | sql | var_usage is on local variable (no sharing) |

| `existing_lock_covers` | PROVEN_SAFE | sql | Lock op in same function covers this var_usage line |

### 5.4 Rule Application Order

Rules are applied in priority order. First matching rule determines classification:

```

1. Function-level AUTO_FALSE_POSITIVE (callback, caller_check, factory_return)

→ All sites in function classified as AUTO_FALSE_POSITIVE

2. Site-level AUTO_FALSE_POSITIVE (sizeof_pseudo_deref, safe_variant_used, local_var_only)

→ Individual site classified as AUTO_FALSE_POSITIVE

3. Site-level PROVEN_SAFE (deref_implies_nonnull, guard_covers, perfect_cleanup)

→ Individual site classified as PROVEN_SAFE (no AI review needed)

4. Function-level LOW_RISK (public_api_convention)

→ All remaining sites classified as LOW_RISK

5. Unmatched sites → NEEDS_AI (require AI verification)

```

### 5.5 Site-Level Classification Impact

For null_dereference on IDM data:

| Classification | Sites | Functions | Mechanism |

|---------------|-------|-----------|-----------|

| AUTO_FALSE_POSITIVE (func-level) | ~800 | ~200 | callback, caller_check |

| AUTO_FALSE_POSITIVE (site-level) | ~350 | ~350 | sizeof_pseudo_deref |

| PROVEN_SAFE (deref_implies_nonnull) | ~1,800 | ~600 | prior deref of same var |

| PROVEN_SAFE (guard_covers) | ~1,200 | ~500 | terminating/scope guard |

| LOW_RISK | ~400 | ~150 | public_api_convention |

| **NEEDS_AI** | **~350** | **~250** | — |

AI review: from 1,334 functions → ~350 sites in ~250 functions (**74% reduction**).

---

## 6. Backfill & Tier System Adaptation

### 6.1 Current Tier System

```

candidate_query (broad) → tier1 (narrower) → tier2 (narrowest)

Priority 3 (deep_backfill)  Priority 2 (backfill)  Priority 1 (core)

```

Tasks are created in priority order. Lower priority tasks are HELD until higher priority tasks prove their TP rate.

**Problem**: Tier boundaries are at the function level. A function with 5 deref_sites (2 high-risk, 3 low-risk) is placed in a single tier based on the worst site.

### 6.2 Site-Level Tier System

Replace function-level tiering with **site-level risk scoring**:

```python

def site_risk_score(site_classification, site_facts) -> int:

"""Return risk score 1-3 for a site."""

if site_classification == "NEEDS_AI":

# Check site-level risk indicators

if is_param_deref_without_any_guard(site_facts):

return 1  # High risk: first-line param deref, no guard at all

elif is_alloc_deref(site_facts):

return 1  # High risk: alloc return deref (malloc can return NULL)

else:

return 2  # Medium risk: other NEEDS_AI sites

elif site_classification == "LOW_RISK":

return 3  # Low risk: will only be reviewed if core has high TP rate

else:

return 0  # PROVEN_SAFE / AUTO_FALSE_POSITIVE: not scheduled

```

### 6.3 Task Grouping with Mixed-Risk Sites

A function may have sites at different risk levels. Strategy:

```

function F has sites: [s1(risk=1), s2(risk=1), s3(risk=2), s4(PROVEN_SAFE)]

→ Create 2 tasks:

1. task_f1_core: function_id=F, site_ids=[s1, s2], priority=1

2. task_f1_backfill: function_id=F, site_ids=[s3], priority=2

3. s4 is PROVEN_SAFE → not scheduled

```

**Worker efficiency**: When the core task executes, it receives the full evidence package including PROVEN_SAFE sites (for context). The Worker only needs to verify the NEEDS_AI sites.

### 6.4 Backfill Decision at Site Level

```

After all priority-1 sites complete:

TP_rate = confirmed_findings / total_priority_1_sites

if TP_rate >= 20%:

upgrade all priority-2 sites to NEW

elif TP_rate >= 5%:

sample 20% of priority-2 sites

else:

sample 1 batch of priority-2 sites

After priority-2 completes:

Same logic for priority-3 sites

```

This is the same gating logic as current, but operating on site counts rather than function counts, giving finer-grained control.

---

## 7. Implementation Plan

### Phase 1: Foundation (Changes 1-2, lowest risk)

#### Change 1: Fix null_guards scope_start/scope_end

Already designed in the existing plan. Fill scope_start/scope_end from AST during extraction.

**Files**: c_extractor.py, models.py, writer.py, indexer.py, reader.py

**Impact**: Restores guard coverage analysis for all skills that use null_guards (null_dereference, out_of_bounds, use_after_free, nullability_contract, security.input_validation).

#### Change 2: Add sizeof_pseudo_deref site-level rule

Detect deref_kind='star' sites where the deref is inside a sizeof() expression. These are type expressions, not runtime dereferences.

**Implementation**:

- In c_extractor.py: tag deref_sites with `is_type_expr` flag when inside sizeof/alignof/_Alignof

- In candidates.py: add site-level SQL rule `sizeof_pseudo_deref`

- In rule_predicates.py: add `is_sizeof_pseudo_deref(func_id, site_id, db)` predicate

**Impact**: ~30 functions on IDM have sizeof(*ptr) inside malloc. Eliminates these false candidates.

### Phase 2: Site-Level Infrastructure (Changes 3-5)

#### Change 3: Extend task schema for site-level verification

**Files**: models.py, store/writer.py, store/reader.py, runtime/planner.py, cli.py

- Add `site_ids`, `site_kind`, `evidence_ref` columns to verification_task

- Update plan_skill() to create per-function tasks instead of batched tasks

- Add evidence file generation to plan_skill()

#### Change 4: Implement SkillEvidenceSpec and evidence pre-fetch

**Files**: New file `sgre/src/sgre/query/evidence.py`

- Define SkillEvidenceSpec dataclass

- Implement evidence pre-fetch for each skill

- Write evidence JSON files during plan phase

- Update Worker prompt to reference evidence file

#### Change 5: Implement site-level rule engine

**Files**: query/engine.py, query/candidates.py, query/rule_predicates.py

- Extend RuleCheck to support site-level predicates

- Add site-level rules for top-5 skills (null_dereference, memory_leak, double_free, buffer_overflow, missing_lock)

- Add deref_implies_nonnull predicate

- Update _apply_rules() to operate at site level

### Phase 3: Cross-Skill Rollout (Changes 6-8)

#### Change 6: Add site-level rules for remaining Category A skills

- use_after_free: post_release_null_guard, release_then_assign_null

- invalid_free: stack_var_check, alloc_source_match

- allocator_mismatch: same_allocator_family

- resource_leak: fd_passed_to_child, socket_lifetime

- lock_misuse: trylock_pattern, recursive_lock_same_mutex

- lock_order: consistent_order_across_functions

- must_check: void_return_ignored, error_code_propagated

- output_encoding: constant_output, internal_buffer

- error_propagation: error_already_propagated, fatal_exit_path

- ownership_transfer: unique_ptr_moved, moved_from_check

#### Change 7: Add site-level tier system

**Files**: runtime/planner.py, query/engine.py

- Replace function-level tier partitioning with site-level risk scoring

- Group same-function sites by risk level into separate tasks

- Update backfill gating to operate on site counts

#### Change 8: Update Worker integration

**Files**: secguard.md (Dispatcher), SKILL.md files

- Update Dispatcher to read evidence_ref from task

- Update Worker prompt template to include evidence package

- Update SKILL.md Stage A-F to reference pre-fetched evidence

---

## 8. Expected Funnel Convergence by Skill (IDM Projections)

### 8.1 High-Impact Skills (large candidate pools)

| Skill | L0 Functions | L1 Candidates | L2 After SQL filter | L3 After site-level rules | L4 AI Review (sites) | Compression |

|-------|-------------|---------------|--------------------|--------------------------|--------------------|-------------|

| null_dereference | 4,410 | 1,385 | 1,220 | ~700 | ~350 sites / ~250 funcs | 74% |

| memory_leak | 4,410 | 574 | 400 | ~250 | ~120 alloc sites / ~80 funcs | 79% |

| use_after_free | 4,410 | ~300 | ~250 | ~150 | ~60 release+deref pairs | 80% |

| must_check | 4,410 | ~800 | ~600 | ~400 | ~150 call sites | 75% |

| missing_lock | 4,410 | 552 | ~400 | ~250 | ~80 var_usage sites | 80% |

| buffer_overflow | 4,410 | 402 | ~300 | ~200 | ~60 buffer_op sites | 80% |

### 8.2 Medium-Impact Skills (moderate candidate pools)

| Skill | L0 Functions | L1 Candidates | L2 After filter | L3 After rules | L4 AI Review | Compression |

|-------|-------------|---------------|----------------|----------------|-------------|-------------|

| double_free | 4,410 | ~200 | ~150 | ~80 | ~30 release pairs | 85% |

| out_of_bounds | 4,410 | ~350 | ~250 | ~120 | ~50 deref sites | 86% |

| allocator_mismatch | 4,410 | ~150 | ~120 | ~80 | ~20 alloc+release pairs | 87% |

| lock_misuse | 4,410 | 44 | ~35 | ~20 | ~8 lock_op pairs | 77% |

| error_propagation | 4,410 | ~400 | ~300 | ~150 | ~60 call sites | 80% |

### 8.3 Low-Impact Skills (small candidate pools or function-level)

| Skill | L1 Candidates | L4 AI Review | Notes |

|-------|---------------|-------------|-------|

| integer_overflow | ~200 | ~150 | Function-level, few auto_fp opportunities |

| assignment_in_condition | ~100 | ~80 | AST pattern, function-level |

| operator_precedence | ~80 | ~60 | AST pattern, function-level |

| signed_unsigned_compare | ~120 | ~90 | AST pattern, function-level |

| suspicious_boolean | ~60 | ~40 | AST pattern, function-level |

| nullability_contract | ~50 | ~30 | Annotation-based, very few annotations in IDM |

| capability_contract | ~30 | ~20 | Annotation-based, very few in IDM |

### 8.4 Aggregate Impact

| Metric | Current | After Phase 2 | After Phase 3 |

|--------|---------|---------------|---------------|

| Total AI review functions (all skills) | ~4,000 | ~1,800 | ~1,200 |

| Total AI review sites | N/A (function-level) | ~1,200 | ~900 |

| Estimated total tokens | ~2.1M | ~1.0M | ~0.8M |

| Task count | ~150 | ~300 | ~250 |

| Avg tokens per task | ~14,000 | ~3,300 | ~3,200 |

---

## 9. Design Principles & Trade-offs

### 9.1 Why Site-Level, Not Just Better SQL

The SQL candidate_query already filters broadly. The remaining gap is:

1. **SQL can't express deref-implies-nonnull**: "Was this variable dereferenced on an earlier line?" requires ordered site-level reasoning within a function

2. **SQL can't express scope coverage precisely**: "Is this deref inside a guard's scope?" requires range intersection (line BETWEEN scope_start AND scope_end)

3. **SQL can't express cross-site dependency**: "Does this alloc site have a matching release on every path?" requires per-site path analysis

These are inherently site-level questions. Function-level auto_fp rules miss them.

### 9.2 Why Pre-Fetch Evidence

Current Workers execute 5-10 SQL queries per function. With site-level tasks:

- Same-function sites share 70-90% of evidence (function body, params, guards)

- Pre-fetching eliminates redundant queries

- Evidence JSON is ~4,800 tokens vs ~7,500 tokens for full function body + queries

- Worker can start reasoning immediately without I/O latency

### 9.3 Why Per-Function Tasks (Not Per-Site)

- Single-site tasks would create 10,724 tasks for null_dereference alone (too many for runtime DB)

- Same-function sites share context — separating them forces evidence duplication or complex cross-referencing

- Worker naturally processes one function at a time (reads source, understands control flow)

- Grouping same-function sites preserves shared reasoning while still enabling site-level filtering

### 9.4 Category B Skills Stay Function-Level

8 skills (integer_overflow, nullability_contract, capability_contract, assignment_in_condition, operator_precedence, signed_unsigned_compare, suspicious_boolean, api_semantic_misuse) have no natural site decomposition. Their verification question is "does this function contain the pattern?" not "is this site safe?"

For these skills:

- site_ids = [] in task schema

- evidence_ref contains only shared_facts (no site_facts)

- No site-level rules (only function-level rules)

- Current task model is already optimal

This is fine — the unified schema handles both cases naturally.

### 9.5 Backward Compatibility

The proposed schema is a strict superset of the current schema:

```python

# Current task can be losslessly mapped to proposed:

task = VerificationTask(

function_id=batch_of_funcs[0],  # First function

site_ids=[],                     # Empty = function-level

site_kind="function",

evidence_ref=None,               # Worker fetches itself (backward compat)

)

```

Migration path:

1. Add new columns (nullable) to verification_task

2. Update plan_skill() to populate new columns for skills with SkillEvidenceSpec

3. Workers without SkillEvidenceSpec continue using old path (no evidence_ref)

4. Gradually add SkillEvidenceSpec for each skill

---

## 10. Risk Analysis

### 10.1 Over-Filtering Risk

Site-level PROVEN_SAFE rules could incorrectly mark a genuine vulnerability as safe.

**Mitigation**:

- PROVEN_SAFE rules must be **conservative**: only mark a site as PROVEN_SAFE when the evidence is unambiguous

- deref_implies_nonnull: Only applies when the prior deref is on the **same variable** and on an **earlier line** in the **same function**

- sizeof_pseudo_deref: Only applies when deref_kind='star' AND inside sizeof/alignof

- guard_covers: Only applies when scope_start/scope_end are populated (not NULL/0)

**Safety check**: Run new rules on c-vuln-benchmark. If any genuine vulnerability is marked PROVEN_SAFE, the rule is too aggressive and must be tightened.

### 10.2 Evidence Staleness Risk

Pre-fetched evidence could become stale if the source code changes between plan and execution.

**Mitigation**:

- Evidence files include a content_hash of the source file

- Worker verifies content_hash matches current file before reasoning

- If mismatch, Worker re-fetches evidence (graceful degradation)

### 10.3 Task Count Explosion

Per-function tasks increase task count from ~50 to ~250 for null_dereference.

**Mitigation**:

- Runtime DB handles 250 tasks easily (SQLite can handle millions of rows)

- Dispatcher groups tasks into concurrent Worker batches (same as current)

- Task creation is fast (batch INSERT, not per-task I/O)

---

## Appendix A: Verification Unit Reference Table

| Verification Unit | Description | Example Question | Skills |

|---|---|---|---|

| deref_site | Pointer dereference (->, *, []) | "Is msg->data safe at line 42?" | null_dereference, out_of_bounds, use_after_free |

| alloc_site | Heap allocation | "Is malloc(100) at line 15 leaked?" | memory_leak, uninitialized, resource_leak |

| release_site | Heap/resource release | "Is free(ptr) at line 30 double-freed?" | double_free, double_release |

| alloc+release_pair | Allocation + release pair | "Does malloc at L10 match free at L30?" | allocator_mismatch, resource_lifecycle, invalid_free |

| buffer_op | Buffer operation (memcpy, strcpy, etc.) | "Is memcpy(dst, src, len) at L20 safe?" | buffer_overflow |

| lock_op_pair | Lock acquire + release pair | "Is mutex_lock at L5 paired with unlock?" | lock_misuse, lock_order |

| call_site | Function call | "Is return value of malloc checked?" | must_check, output_encoding, error_propagation, refcount_misuse |

| var_usage_site | Variable access | "Is g_counter access at L10 protected?" | missing_lock |

| assignment_site | Variable assignment | "Does state=ACTIVE at L15 follow valid transition?" | ownership_transfer, state_transition |

| function | Entire function body | "Does this function have assignment in condition?" | assignment_in_condition, operator_precedence, signed_unsigned_compare, suspicious_boolean, integer_overflow, nullability_contract, capability_contract, api_semantic_misuse |

## Appendix B: Fact Table Dependency Matrix

| Skill | alloc | release | deref | buffer | lock | call | assign | var_use | guard | param | var | goto | return | annot |

|-------|-------|---------|-------|--------|------|------|--------|---------|-------|-------|-----|------|--------|-------|

| null_dereference | Y | | Y | | | | Y | | Y | Y | Y | | | |

| out_of_bounds | Y | | Y | | | | Y | | Y | Y | Y | | | |

| use_after_free | Y | Y | Y | | | | Y | | Y | | | | | |

| double_free | Y | Y | | | | | Y | | Y | | | | | |

| invalid_free | Y | Y | | | | | | | | Y | | | | |

| memory_leak | Y | Y | | | | Y | Y | | | | | Y | Y | |

| uninitialized | Y | | | | | | Y | | | | | | Y | |

| allocator_mismatch | Y | Y | | | | | | | | | | Y | Y | |

| buffer_overflow | Y | | | Y | | | Y | | | | | | Y | |

| resource_lifecycle | Y | Y | | | | | | | | | | | | |

| double_release | | Y | | | | | | | | | | | | |

| resource_leak | Y | Y | | | | | | | | | | Y | Y | |

| lock_misuse | | | | | Y | | | | | | | | Y | |

| lock_order | | | | | Y | | | | | | | | | |

| missing_lock | | | | | Y | | | Y | | | Y | | | | |

| refcount_misuse | | | | | | Y | | | | | | | Y | |

| must_check | | | | | | Y | | | | | | | | Y |

| output_encoding | | | | | | Y | | | | Y | | | | |

| input_validation | | | Y | | | Y | | | Y | Y | | | | |

| error_propagation | | | | | | Y | | | | | | | Y | |

| ownership_transfer | | | | | | Y | | | | | | | | |

| state_transition | | | | | | | Y | | | | | | Y | |

| nullability_contract | | | | | | Y | | | | | | | | Y |

| capability_contract | | | | | | | | | | | | | | Y |

| integer_overflow | | | | | | Y | | | | | | | | |

| api_semantic_misuse | | | | | | Y | | | | | | | | |

| assignment_in_condition | | | | | | | | | | | | | | |

| operator_precedence | | | | | | | | | | | | | | |

| signed_unsigned_compare | | | | | | | | | | | | | | |

| suspicious_boolean | | | | | | | | | | | | | | |