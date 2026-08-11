---
name: memory-leak
description: Classify memory leak evidence — MEMORY_ALLOC without matching MEMORY_RELEASE on all paths. Maps to CWE-401.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-401
  severity: MEDIUM
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