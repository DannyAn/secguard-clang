# Buffer Overflow in use_buffer

**CWE:** CWE-787

## Location

- **File:** `<ROOT>/src/a.c:9`
- **Function:** `use_buffer`
- **Variable:** `buf`

## Code Context

`<ROOT>/src/a.c:1-20` — line 9 is the reported location.

```c
   1 | #include <stdlib.h>
   2 |
   3 | int read_value(const char *p) {
   4 |     return *p;
   5 | }
   6 |
   7 | int use_buffer(int n) {
   8 |     char buf[4];
>  9 |     buf[n] = 'x';
  10 |     return buf[0];
  11 | }
  12 |
  13 | int leak_fd(void) {
  14 |     int fd = 3;
  15 |     return fd;
  16 | }
  17 |
  18 | int unchecked(int *p) {
  19 |     return p[0];
  20 | }
```

## Evidence

- (no pipeline evidence package recorded for this location)

## Classification

- **Status:** confirmed (severity: high, confidence: 100%)

## Summary

index n is not bounds-checked against buf[4]

## Reasoning

detector proved the write reaches buf with an unguarded index
