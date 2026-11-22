# Null Deref in read_value

**CWE:** CWE-476

## Location

- **File:** `<ROOT>/src/a.c:4`
- **Function:** `read_value`
- **Variable:** `p`

## Code Context

`<ROOT>/src/a.c:1-19` — line 4 is the reported location.

```c
   1 | #include <stdlib.h>
   2 |
   3 | int read_value(const char *p) {
>  4 |     return *p;
   5 | }
   6 |
   7 | int use_buffer(int n) {
   8 |     char buf[4];
   9 |     buf[n] = 'x';
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
```

## Evidence

- (no pipeline evidence package recorded for this location)

## Classification

- **Status:** confirmed (severity: high, confidence: 90%)

## Summary

p is dereferenced without a NULL check

## Reasoning

get_ptr may return NULL on the negative path

## Exception Check

none

## Fix Strategy

Return early when p is NULL.
