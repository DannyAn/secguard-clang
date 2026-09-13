---
name: memory-leak
description: Classify memory leak evidence — MEMORY_ALLOC without matching MEMORY_RELEASE on all paths. Maps to CWE-401.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: CWE-401
  severity: MEDIUM
  domain: memory
---

## Memory Leak Analysis (CWE-401)

### Evidence Pattern
A memory-leak candidate has:
- **MEMORY_ALLOC event**: malloc/calloc/realloc allocation
- **No MEMORY_RELEASE**: No corresponding free on some code path
- **Reachable**: The function is reachable from an entry point

### Counter-Evidence Patterns (P2)

| Pattern | Detection | Why Safe |
|---------|-----------|----------|
| RAII (ResourceHandle) | create+destroy pair in same scope | Destructor frees on scope exit |
| Cleanup function | `cleanup_entries()` frees all | Centralized cleanup |
| Freeing macro | `#define SAFE_FREE(p) ...` / `#define my_free(p) free(p)` | The macro wraps `free`, which is now recognized — not a leak |
| Reference counting | `ref_count--` before free | Freed when ref count hits 0 |
| `free` on all paths | Both success and error paths free | No leak path |

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| malloc + no free on any path | **confirmed** |
| malloc + free on success path only, not error path | **confirmed** (error path leak) |
| malloc + free on all paths | **false-positive** |
| malloc inside RAII wrapper (create+destroy) | **false-positive** |
| malloc + returned to caller (ownership transfer) | **false-positive** (caller owns) |
| malloc + stored in global/static | **suspected** (may be freed elsewhere) |

### Path-Sensitive Analysis
The key question: Is there a path from malloc to function exit that does NOT pass through free?

```
malloc → if (error) return;  ← LEAK (no free before return)
malloc → if (error) { free(p); return; }  ← SAFE (free on all paths)
```

### Fix Suggestions
- Free on all error paths: `if (err) { free(buf); return -1; }`
- Use RAII pattern: `ResourceHandle *h = ResourceHandle_create(n); ... ResourceHandle_destroy(h);`
- Use cleanup attribute: `__attribute__((cleanup(free_fn)))`
- Ensure ownership is clear: document who is responsible for freeing

### Severity Matrix

`status` and `severity` are independent: `status` = evidence verdict
(confirmed/suspected/dismissed), `severity` = impact (low/medium/high/critical).
`metadata.severity` is the type default, not a ceiling. Suspected findings are
capped one notch below their confirmed twin (evidence discount), never below
`low`; dismissed → `low`.

| Shape | Lifetime / frequency | Severity |
|-------|---------------------|----------|
| One-shot allocation, low call frequency / short lifetime | Low | MEDIUM |
| Long-lived service, or a per-request / per-iteration leak | High | HIGH |
| Unbounded continuous leak → resource exhaustion / service restart | Unbounded | CRITICAL |
| Ownership unsettled (stored in global/static, may be freed elsewhere) | Unsettled | MEDIUM (suspected; LOW if one-shot) |