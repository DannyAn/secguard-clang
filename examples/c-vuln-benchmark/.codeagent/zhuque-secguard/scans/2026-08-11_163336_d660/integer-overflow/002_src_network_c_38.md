# Integer Overflow in parse_packet

**CWE:** CWE-190

## Location

- **File:** `/Users/kongan/workbench/github/secguard-lite/examples/c-vuln-benchmark/src/network.c:38`
- **Function:** `parse_packet`
- **Variable:** `header->data_size + HEADER_SIZE`

## Evidence

- **integer_overflow:** arithmetic overflow in size calculation in parse_packet at line 38
- **call_path:** function parse_packet is reachable from entry
- **weak_guard:** guard exists but is insufficient (partial protection, needs AI review)

## Classification

- **Suspicion Level:** suspected
- **Status:** _pending_ (awaiting agent classification)

## Fix Suggestion

Check for integer overflow before using the result in memory allocation
or buffer operations in `parse_packet`:

```c
// Check a + b > SIZE_MAX before allocating
if (a > SIZE_MAX - b) {
    return NULL;  // overflow would occur
}
size_t total = a + b;
char *buf = malloc(total);
```

Use `size_t` for sizes (never `int`), and prefer checked-arithmetic
helpers like `__builtin_add_overflow` (GCC/Clang) or manual bounds
checks. Clamp `count * elem_size` products before passing to `malloc`/`memcpy`.
