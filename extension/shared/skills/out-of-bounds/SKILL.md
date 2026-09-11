---
name: out-of-bounds
description: Classify out-of-bounds read evidence — BUFFER_ACCESS events with array_oob_read/heap_oob_read categories. Maps to CWE-125.
license: MIT
compatibility: opencode
metadata:
  cwe: CWE-125
  severity: HIGH
  domain: boundary
---

## Out-of-Bounds Analysis (CWE-125)

### Evidence Pattern
An out-of-bounds candidate has:
- **BUFFER_ACCESS event** with category `array_oob_read` (fixed-size array read
  past its declared size) or `heap_oob_read` (loop bound past a
  `malloc`/`calloc` allocation)
- The subscript appears on the read side of an expression, e.g.
  `secret = arr[i];` or `sum += buf[i];`
- **Reachable**: the function is reachable from an entry point

### Typical Example
```c
int arr[10];
for (int i = 0; i <= 10; i++) {   /* i == 10 is out of bounds */
    secret = arr[i];              /* read past the array */
}
```

### Classification Rules

| Condition | Classification |
|-----------|---------------|
| Constant index (or a constant-valued variable `int n = 12; arr[n]`) >= array size, or loop bound provably overruns size | **confirmed** |
| Access guarded by a bounds check covering the read | **false-positive** |
| `sizeof(arr)` usage (not an element access) | **false-positive** |

An index that cannot be proven out-of-bounds (`buf[i]` with an unknown `i`) is
**not emitted at all** — the detector only reports OOB it can prove (constant
index past a known size, or a loop bound that provably overruns it).

### Fix Suggestions
- Change the loop to `i < arr_size` or `i <= arr_size - 1`
- Check the index against the allocation size before dereferencing
- Use `snprintf`-style sized APIs when reading from formatted buffers
