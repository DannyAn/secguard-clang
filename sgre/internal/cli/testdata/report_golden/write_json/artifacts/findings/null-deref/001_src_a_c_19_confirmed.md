# Null Deref in unchecked

**CWE:** CWE-476

## Location

- **File:** `<ROOT>/src/a.c:19`
- **Function:** `unchecked`
- **Variable:** `q`

## Code Context

`<ROOT>/src/a.c:4-20` — line 19 is the reported location.

```c
   4 |     return *p;
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
> 19 |     return p[0];
  20 | }
```

## Evidence

- (no pipeline evidence package recorded for this location)

## Classification

- **Status:** confirmed (severity: high, confidence: 92%)

## Summary

p is indexed without a bounds check

## Reasoning

the index is not validated before the read

## Exception Check

no exception path covers the read

## Fix Strategy

Validate the index against the allocation size.
